package geoip

import (
	"archive/tar"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/samaasi/go-waf/internal/domain"
)

const maxDatabaseSize = 200 * 1024 * 1024

func EnsureDatabase(editionID, licenseKey, localPath string, log domain.Logger) (bool, error) {
	if licenseKey == "" {
		return false, fmt.Errorf("missing MaxMind license key")
	}

	url := fmt.Sprintf("https://download.maxmind.com/app/geoip_download?edition_id=%s&license_key=%s&suffix=tar.gz", editionID, licenseKey)

	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	resp, err := client.Head(url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	remoteModTime, _ := time.Parse(time.RFC1123, resp.Header.Get("Last-Modified"))
	localInfo, err := os.Stat(localPath)
	if err == nil && !remoteModTime.After(localInfo.ModTime()) {
		log.Debug("GeoIP database is up to date", domain.String("edition", editionID))
		return false, nil
	}

	log.Info("Downloading newer GeoIP database", domain.String("edition", editionID))

	resp, err = client.Get(url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("maxmind api returned status %d", resp.StatusCode)
	}

	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return false, err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	tempPath := localPath + ".tmp"

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, err
		}

		if strings.HasSuffix(header.Name, ".mmdb") {
			f, err := os.OpenFile(tempPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				return false, err
			}

			written, err := io.Copy(f, io.LimitReader(tr, maxDatabaseSize))
			f.Close()
			if err != nil {
				os.Remove(tempPath)
				return false, err
			}
			if written >= maxDatabaseSize {
				os.Remove(tempPath)
				return false, fmt.Errorf("database exceeds %d byte limit — possible zip-bomb", maxDatabaseSize)
			}

			// Validate the downloaded file is a valid mmdb before swapping
			if err := validateMMDB(tempPath); err != nil {
				os.Remove(tempPath)
				return false, fmt.Errorf("downloaded database validation failed: %w", err)
			}

			if err := os.Rename(tempPath, localPath); err != nil {
				return false, err
			}

			log.Info("GeoIP database updated successfully", domain.String("edition", editionID))
			return true, nil
		}
	}

	return false, fmt.Errorf("mmdb file not found in archive")
}

func validateMMDB(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() < 1024 {
		return fmt.Errorf("file too small to be a valid mmdb (%d bytes)", info.Size())
	}
	return nil
}
