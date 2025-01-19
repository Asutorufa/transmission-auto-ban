package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hekmon/cunits/v2"
	"github.com/hekmon/transmissionrpc/v3"
	"go.etcd.io/bbolt"
	"gvisor.dev/gvisor/pkg/tcpip"
)

type entry struct {
	time   uint64
	addr   string
	client string
}

func main() {
	blockfile := flag.String("file", "blocklist.txt", "file path")
	dbfile := flag.String("db", "blocklist.db", "blocklist db path")
	rpc := flag.String("rpc", "http://127.0.0.1:9091/transmission/rpc", "transmission rpc url")
	lishost := flag.String("host", ":9092", "listen host")
	flag.BoolVar(&iptEnabled, "iptables", false, "enable iptables")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
	})))
	db, err := NewDB(*dbfile)
	if err != nil {
		panic(err)
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

	initRule(filepath.Dir(*dbfile))

	tban := &TBan{db, cli, *blockfile}

	go func() {
		timer := time.NewTicker(time.Minute * 2)
		defer timer.Stop()

		tban.Run()
		for range timer.C {
			tban.Run()
		}
	}()

	go func() {
		timer := time.NewTicker(time.Hour)
		defer timer.Stop()

		for range timer.C {
			refreshRule(filepath.Dir(*dbfile))
		}
	}()

	if err := http.ListenAndServe(*lishost, http.FileServer(&fm{*blockfile})); err != nil {
		panic(err)
	}
}

func isToStop(v transmissionrpc.Torrent) bool {
	if v.UploadRatio != nil && *v.UploadRatio >= 3 {
		return true
	} else if v.AddedDate != nil && time.Since(*v.AddedDate) > time.Hour*24*30*6 &&
		v.TotalSize != nil && *v.TotalSize < cunits.Gibit*5 {
		return true
	} else if v.UploadRatio != nil && *v.UploadRatio >= 2.2 &&
		v.AddedDate != nil && time.Since(*v.AddedDate) > time.Hour*24*30*3 &&
		v.TotalSize != nil && *v.TotalSize < cunits.Gibit*5 {
		return true
	} else if v.AddedDate != nil && time.Since(*v.AddedDate) > time.Hour*24*30*12 {
		return true
	}

	return false
}

type TBan struct {
	db   *DB
	cli  *transmissionrpc.Client
	path string
}

func (t *TBan) Run() {
	if err := t.run(); err != nil {
		slog.Error("run", "err", err)
	}
}

func (t *TBan) run() error {
	at, err := t.cli.TorrentGetAll(context.Background())
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

		if isToStop(v) {
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
				slog.Info("torrent", "address", p.Address, "client", p.ClientName)
			}
		}
	}

	t.db.addBlock(clientAddress...)

	defer func() {
		entries, err := t.cli.BlocklistUpdate(context.Background())
		if err != nil {
			slog.Error("BlocklistUpdate", "err", err)
		} else {
			slog.Info("BlocklistUpdate", "entries", entries)
		}
	}()

	w, err := NewBlacklistWriter(t.path)
	if err != nil {
		return err
	}
	defer w.Close()

	addresses := []string{}
	t.db.rangeBlock(func(tx *bbolt.Bucket, v entry) {
		addresses = append(addresses, v.addr)
		_, _ = fmt.Fprintf(w, "Autogen[%s]:%s-%s\n", v.client, v.addr, v.addr)
	}, time.Hour*24*2)

	for _, v := range ips {
		addr, err := netip.ParseAddr(v)
		if err == nil {
			_, _ = fmt.Fprintf(w, "Autogen[%s]:%s-%s\n", "pbh", addr.Unmap().String(), addr.Unmap().String())
			continue
		}

		prefix, err := netip.ParsePrefix(v)
		if err == nil {
			addr := tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice(prefix.Addr().AsSlice()), PrefixLen: prefix.Bits()}

			subnet := addr.Subnet()
			last := subnet.Broadcast()

			_, _ = fmt.Fprintf(w, "Autogen[%s]:%s-%s\n", "pbh", prefix.Addr().Unmap().String(), netip.MustParseAddr(last.String()).Unmap().String())
			continue
		}

		continue
	}

	if len(stopTorrents) > 0 {
		slog.Info("stop torrents", "torrents", stopTorrents)
		_ = t.cli.TorrentStopIDs(context.Background(), stopTorrents)
	}

	if iptEnabled {
		if err := nft(append(addresses, ips...)); err != nil {
			slog.Error("nftable apply failed", "err", err)
		}

		// if err := it(append(addresses, ips...)); err != nil {
		// log.Println("it", err)
		// }
	} else {
		restartTorrents(t.cli, torrents)
	}

	return nil
}

func restartTorrents(cli *transmissionrpc.Client, torrents []int64) {
	if len(torrents) == 0 {
		return
	}

	slog.Info("restart torrents", "torrents", torrents)

	err := cli.TorrentStopIDs(context.Background(), torrents)
	if err != nil {
		slog.Error("TorrentStopIDs failed", "err", err)
		return
	}

	for range 3 {
		time.Sleep(time.Second * 3)
		err = cli.TorrentStartIDs(context.Background(), torrents)
		if err != nil {
			slog.Error("TorrentStartIDs", "err", err, "torrents", torrents)
		} else {
			break
		}
	}
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

type blacklistWriter struct {
	txt *os.File
	fgz *os.File
	gw  *gzip.Writer

	bw *bufio.Writer
}

func NewBlacklistWriter(path string) (*blacklistWriter, error) {
	f, err := os.OpenFile(path, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	fgz, err := os.OpenFile(path+".gz", os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	gw := gzip.NewWriter(fgz)

	bw := bufio.NewWriter(io.MultiWriter(f, gw))

	return &blacklistWriter{f, fgz, gw, bw}, nil
}

func (bw *blacklistWriter) Close() error {
	if err := bw.bw.Flush(); err != nil {
		return err
	}

	if err := bw.gw.Close(); err != nil {
		return err
	}

	if err := bw.fgz.Close(); err != nil {
		return err
	}

	if err := bw.txt.Close(); err != nil {
		return err
	}

	return nil
}

func (bw *blacklistWriter) Write(p []byte) (int, error) {
	return bw.bw.Write(p)
}

type DB struct {
	db *bbolt.DB
}

func NewDB(path string) (*DB, error) {
	err := os.MkdirAll(filepath.Dir(path), 0755)
	if err != nil {
		return nil, err
	}
	db, err := bbolt.Open(path, 0666, nil)
	if err != nil {
		return nil, err
	}

	return &DB{db}, nil
}

func (d *DB) addBlock(name ...entry) {
	err := d.db.Batch(func(tx *bbolt.Tx) error {
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
	if err != nil {
		slog.Error("addBlock", "err", err)
	}
}

func (d *DB) rangeBlock(f func(tx *bbolt.Bucket, v entry), expireDuration time.Duration) {
	err := d.db.Batch(func(tx *bbolt.Tx) error {
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

	if err != nil {
		slog.Error("rangeBlock", "err", err)
	}
}
