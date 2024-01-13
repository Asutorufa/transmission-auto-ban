package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/hekmon/transmissionrpc/v3"
	"go.etcd.io/bbolt"
)

var addBlock func(name ...string) = func(name ...string) {}

var rangeBlock func(f func(tx *bbolt.Bucket, k string, v int64), expireDuration time.Duration) = func(f func(tx *bbolt.Bucket, k string, v int64), expireDuration time.Duration) {}

func main() {
	blockfile := flag.String("file", "blocklist.txt", "file path")
	dbfile := flag.String("db", "blocklist.db", "blocklist db path")
	rpc := flag.String("rpc", "http://127.0.0.1:9091/transmission/rpc", "transmission rpc url")
	lishost := flag.String("host", ":9092", "listen host")
	flag.Parse()

	_ = os.MkdirAll(filepath.Dir(*dbfile), 0755)
	db, err := bbolt.Open(*dbfile, 0666, nil)
	if err != nil {
		panic(err)
	}

	addBlock = func(name ...string) {
		_ = db.Batch(func(tx *bbolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists([]byte("blocklist"))
			if err != nil {
				return err
			}

			nowBytes := binary.BigEndian.AppendUint64(nil, uint64(time.Now().Unix()))
			for _, v := range name {
				_ = b.Put([]byte(v), nowBytes)
			}

			return nil
		})
	}

	rangeBlock = func(f func(tx *bbolt.Bucket, k string, v int64), expireDuration time.Duration) {
		_ = db.Batch(func(tx *bbolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists([]byte("blocklist"))
			if err != nil {
				return err
			}

			now := time.Now().Unix()
			_ = b.ForEach(func(k, v []byte) error {
				if len(v) != 8 {
					_ = b.Delete(k)
					return nil
				}

				timeBytes := binary.BigEndian.Uint64(v)

				if time.Second*(time.Duration(now)-time.Duration(timeBytes)) > expireDuration {
					_ = b.Delete(k)
					return nil
				}

				f(b, string(k), int64(timeBytes))

				return nil
			})

			return nil
		})
	}

	url, err := url.Parse(*rpc)
	if err != nil {
		panic(err)
	}

	cli, err := transmissionrpc.New(url, nil)
	if err != nil {
		panic(err)
	}

	_, err = os.Stat(*blockfile)
	if err != nil && os.IsNotExist(err) {
		_ = os.MkdirAll(filepath.Dir(*blockfile), 0755)
		f, err := os.Create(*blockfile)
		if err != nil {
			panic(err)
		}
		f.Close()
	}

	regexps := []*regexp.Regexp{}

	for _, v := range []string{
		"xunlei",
		"thunder",
		`gt[[:digit:]]{4}`,
		`GT[[:digit:]]{4}`,
		"xl0012",
		"xf",
		"dandanplay",
		"dl3760",
		"qq",
		"libtorrent",
	} {
		rg, err := regexp.Compile(v)
		if err != nil {
			log.Println("compile", v, err)
			continue
		}

		regexps = append(regexps, rg)
	}

	timer := time.NewTicker(time.Minute * 1)
	defer timer.Stop()
	go func() {
		if err := run(cli, regexps, *blockfile); err != nil {
			log.Println("run", err)
		}
		for range timer.C {
			if err := run(cli, regexps, *blockfile); err != nil {
				log.Println("run", err)
			}
		}
	}()

	if err := http.ListenAndServe(*lishost, http.FileServer(&fm{*blockfile})); err != nil {
		panic(err)
	}
}

func run(cli *transmissionrpc.Client, regexps []*regexp.Regexp, path string) error {
	at, err := cli.TorrentGetAll(context.Background())
	if err != nil {
		return err
	}

	clientAddress := []string{}

	for _, v := range at {
		if v.Status == nil || *v.Status != transmissionrpc.TorrentStatusSeed {
			continue
		}

		if len(v.Peers) <= 0 {
			continue
		}

		for _, p := range v.Peers {
			for _, rg := range regexps {
				if rg.MatchString(p.ClientName) {
					clientAddress = append(clientAddress, p.Address)
					fmt.Println(p.Address, p.ClientName)
				}
			}
		}
	}

	addBlock(clientAddress...)

	defer func() {
		entries, err := cli.BlocklistUpdate(context.Background())
		if err != nil {
			log.Println("BlocklistUpdate", err)
		} else {
			log.Println("BlocklistUpdate", entries)
		}
	}()

	f, err := os.OpenFile(path, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	fgz, err := os.OpenFile(path+".gz", os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	gw := gzip.NewWriter(fgz)
	defer gw.Close()

	bw := bufio.NewWriter(io.MultiWriter(f, gw))
	defer bw.Flush()

	_, _ = fmt.Fprintf(bw, "%s - %s , 0 , Test[expire_at:%d]\n", "127.0.0.1", "127.0.0.1", 0)

	rangeBlock(func(tx *bbolt.Bucket, k string, v int64) {
		_, _ = fmt.Fprintf(bw, "%s - %s , 0 , Autogen[expire_at:%d]\n", k, k, v)
	}, time.Hour*24*2)

	return nil
}

type fm struct {
	file string
}

func (f *fm) Open(name string) (http.File, error) {
	tp := strings.TrimPrefix(name, "/")
	if tp != f.file && tp != f.file+".gz" {
		return nil, os.ErrNotExist
	}

	return os.Open(f.file)
}
