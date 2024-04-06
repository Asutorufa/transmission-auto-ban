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
	"strings"
	"time"

	"github.com/hekmon/cunits/v2"
	"github.com/hekmon/transmissionrpc/v3"
	"go.etcd.io/bbolt"
)

type entry struct {
	time   uint64
	addr   string
	client string
}

var addBlock func(name ...entry) = func(name ...entry) {}

var rangeBlock func(f func(tx *bbolt.Bucket, v entry), expireDuration time.Duration) = func(f func(tx *bbolt.Bucket, v entry), expireDuration time.Duration) {}

func main() {
	blockfile := flag.String("file", "blocklist.txt", "file path")
	dbfile := flag.String("db", "blocklist.db", "blocklist db path")
	rpc := flag.String("rpc", "http://127.0.0.1:9091/transmission/rpc", "transmission rpc url")
	lishost := flag.String("host", ":9092", "listen host")
	flag.BoolVar(&iptEnabled, "iptables", false, "enable iptables")
	flag.Parse()

	_ = os.MkdirAll(filepath.Dir(*dbfile), 0755)
	db, err := bbolt.Open(*dbfile, 0666, nil)
	if err != nil {
		panic(err)
	}

	addBlock = func(name ...entry) {
		_ = db.Batch(func(tx *bbolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists([]byte("blocklist"))
			if err != nil {
				return err
			}

			nowBytes := uint64(time.Now().Unix())

			for _, v := range name {
				_ = b.Put([]byte(v.addr), NewT(nowBytes, v.client))
			}

			return nil
		})
	}

	rangeBlock = func(f func(tx *bbolt.Bucket, v entry), expireDuration time.Duration) {
		_ = db.Batch(func(tx *bbolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists([]byte("blocklist"))
			if err != nil {
				return err
			}

			now := time.Now().Unix()
			_ = b.ForEach(func(k, v []byte) error {
				if len(v) < 8 {
					_ = b.Delete(k)
					return nil
				}

				t := t(v)

				timeBytes := t.Time()

				if time.Second*(time.Duration(now)-time.Duration(timeBytes)) > expireDuration {
					_ = b.Delete(k)
					return nil
				}

				f(b, entry{
					time:   timeBytes,
					addr:   string(k),
					client: t.Client(),
				})

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

	timer := time.NewTicker(time.Minute * 2)
	defer timer.Stop()
	go func() {
		if err := run(cli, *blockfile); err != nil {
			log.Println("run", err)
		}
		for range timer.C {
			if err := run(cli, *blockfile); err != nil {
				log.Println("run", err)
			}
		}
	}()

	if err := http.ListenAndServe(*lishost, http.FileServer(&fm{*blockfile})); err != nil {
		panic(err)
	}
}

func run(cli *transmissionrpc.Client, path string) error {
	at, err := cli.TorrentGetAll(context.Background())
	if err != nil {
		return err
	}

	clientAddress := []entry{}
	torrents := []int64{}
	stopTorrents := []int64{}

	for _, v := range at {
		if v.Status == nil || *v.Status != transmissionrpc.TorrentStatusSeed {
			continue
		}

		if v.UploadRatio != nil && *v.UploadRatio >= 3 {
			stopTorrents = append(stopTorrents, *v.ID)
		} else if v.AddedDate != nil && time.Since(*v.AddedDate) > time.Hour*24*30*6 &&
			v.TotalSize != nil && *v.TotalSize < cunits.Gibit*5 {
			stopTorrents = append(stopTorrents, *v.ID)
		} else if v.UploadRatio != nil && *v.UploadRatio >= 2.2 &&
			v.AddedDate != nil && time.Since(*v.AddedDate) > time.Hour*24*30*3 &&
			v.TotalSize != nil && *v.TotalSize < cunits.Gibit*5 {
			stopTorrents = append(stopTorrents, *v.ID)
		} else if v.AddedDate != nil && time.Since(*v.AddedDate) > time.Hour*24*30*12 {
			stopTorrents = append(stopTorrents, *v.ID)
		}

		if len(v.Peers) <= 0 {
			continue
		}

		for _, p := range v.Peers {
			if regexps.MatchString(p.ClientName, strings.ToLower(p.ClientName)) {
				clientAddress = append(clientAddress, entry{addr: p.Address, client: p.ClientName})
				if v.ID != nil {
					torrents = append(torrents, *v.ID)
				}
				fmt.Println(p.Address, p.ClientName)
			}
		}
	}

	addBlock(clientAddress...)

	defer func() {
		entries, err := cli.BlocklistUpdate(context.Background())
		if err != nil {
			log.Println("BlacklistUpdate", err)
		} else {
			fmt.Printf("\rBlacklistUpdate: %d", entries)
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

	// , HQ ENTERTAINMENT:71.127.117.96-71.127.117.103
	// _, _ = fmt.Fprintf(bw, "Test%d%s:%s-%s\n", 0, "", "127.0.0.1", "127.0.0.1")

	addresses := []string{}
	rangeBlock(func(tx *bbolt.Bucket, v entry) {
		// _, _ = fmt.Fprintf(bw, "Autogen%s%d:%s-%s\n",
		// strings.ReplaceAll(v.client, "-", ""), v.time, v.addr, v.addr)

		addresses = append(addresses, v.addr)
		_, _ = fmt.Fprintf(bw, "Autogen[%s]:%s-%s\n", v.client, v.addr, v.addr)
	}, time.Hour*24*2)

	if len(stopTorrents) > 0 {
		log.Println("stop torrents", stopTorrents)
		_ = cli.TorrentStopIDs(context.Background(), stopTorrents)
	}

	if iptEnabled {
		if err := it(append(addresses, ips...)); err != nil {
			log.Println("it", err)
		}
	}

	if iptEnabled || len(torrents) <= 0 {
		return nil
	}

	log.Println("restart torrents", torrents)

	err = cli.TorrentStopIDs(context.Background(), torrents)
	if err != nil {
		log.Println("TorrentStopIDs", torrents, err)
	} else {
		count := 0
	_retry:
		time.Sleep(time.Second * 3)
		err = cli.TorrentStartIDs(context.Background(), torrents)
		if err != nil {
			log.Println("TorrentStartIDs", torrents, err)
			count++
			if count <= 3 {
				goto _retry
			}
		}
	}

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

type t []byte

func NewT(time uint64, client string) t {
	buf := make([]byte, 8+len(client))

	binary.BigEndian.PutUint64(buf, time)
	copy(buf[8:], client)

	return buf
}

func (t t) Time() uint64 {
	if len(t) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(t[:8])
}

func (t t) Client() string {
	if len(t) < 8 {
		return ""
	}
	return string(t[8:])
}
