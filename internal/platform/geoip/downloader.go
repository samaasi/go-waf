package geoip

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/samaasi/go-waf/internal/domain"
)

// EnsureDatabase checks if a newer version of the database exists and downloads it.
func EnsureDatabase(editionID, licenseKey, localPath string, log domain.Logger) (bool, error) {
	if licenseKey == "" {
		return false, fmt.Errorf("missing MaxMind license key")
	}

	url := fmt.Sprintf("https://download.maxmind.com/app/geoip_download?edition_id=%s&license_key=%s&suffix=tar.gz", editionID, licenseKey)

	// Check remote Last-Modified
	client := &http.Client{Timeout: 30 * time.Second}
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

	// Download and extract
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
			f, err := os.OpenFile(tempPath, os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return false, err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return false, err
			}
			f.Close()

			// Atomic swap
			if err := os.Rename(tempPath, localPath); err != nil {
				return false, err
			}

			log.Info("GeoIP database updated successfully", domain.String("edition", editionID))
			return true, nil
		}
	}

	return false, fmt.Errorf("mmdb file not found in archive")
}
