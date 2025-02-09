// generate_corpus.go
package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/golang/snappy"
	kssz "github.com/karalabe/ssz"
)

// newableObject is a generic constraint to require that U's pointer implements kssz.Object.
type newableObject[U any] interface {
	kssz.Object
	*U
}

// generateSeedCorpus is a generic function that collects a valid corpus for a given type
// and writes the results into a zip file at outZipPath.
func generateSeedCorpus[T newableObject[U], U any](kind string, outZipPath string) error {
	// 1) Collect valid corpus from fork directories.
	validCorpus, err := collectValidCorpus[T, U](kind)
	if err != nil {
		return fmt.Errorf("failed to collect valid corpus for type %s: %v", kind, err)
	}

	if len(validCorpus) == 0 {
		fmt.Printf("No valid corpus for %s -> won't create zip.\n", kind)
		return nil
	}

	// 2) Zip valid corpus.
	if err := zipValidCorpus(validCorpus, outZipPath); err != nil {
		return fmt.Errorf("failed to create zip file for type %s: %v", kind, err)
	}

	fmt.Printf("Created %d valid corpus files for %s => %s\n", len(validCorpus), kind, outZipPath)
	return nil
}

func collectValidCorpus[T newableObject[U], U any](kind string) ([][]byte, error) {
	var validCorpus [][]byte
	rootDir := filepath.Join("consensus-spec-tests", "tests", "mainnet")

	// Read every fork dir
	forks, err := os.ReadDir(rootDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %v", rootDir, err)
	}

	for _, fork := range forks {
		path := filepath.Join(rootDir, fork.Name(), "ssz_static", kind, "ssz_random")
		if _, err := os.Stat(path); err != nil {
			// if the directory does not exist, skip it
			continue
		}

		tests, err := os.ReadDir(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read tests in %s: %v", path, err)
		}

		for _, test := range tests {
			filePath := filepath.Join(path, test.Name(), "serialized.ssz_snappy")
			inSnappy, err := os.ReadFile(filePath)
			if err != nil {
				return nil, fmt.Errorf("failed to load snappy ssz binary from %s: %v", filePath, err)
			}

			// Snappy decode
			inSSZ, err := snappy.Decode(nil, inSnappy)
			if err != nil {
				return nil, fmt.Errorf("failed to decode Snappy data from file %s: %v", filePath, err)
			}

			obj := T(new(U))

			if err := kssz.DecodeFromStreamOnFork(bytes.NewReader(inSSZ), obj, uint32(len(inSSZ)), kssz.ForkFuture); err != nil {
				log.Printf("Decode check failed for file %s (type %s): %v", filePath, kind, err)
				continue
			}

			validCorpus = append(validCorpus, inSSZ)
		}
	}

	return validCorpus, nil
}

// zipValidCorpus writes the given valid corpus (slice of SSZ byte slices)
// into a zip file, each as a separate file.
func zipValidCorpus(validCorpus [][]byte, zipFilename string) error {
	zipFile, err := os.Create(zipFilename)
	if err != nil {
		return fmt.Errorf("failed to create zip file: %v", err)
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer func() {
		if err := zipWriter.Close(); err != nil {
			log.Printf("failed to close zip writer: %v", err)
		}
	}()

	for i, data := range validCorpus {
		fileName := fmt.Sprintf("file_%03d.ssz", i)
		fw, err := zipWriter.Create(fileName)
		if err != nil {
			return fmt.Errorf("failed to create zip entry for %s: %v", fileName, err)
		}

		if _, err := io.Copy(fw, bytes.NewReader(data)); err != nil {
			return fmt.Errorf("failed to write data to zip entry %s: %v", fileName, err)
		}
	}

	return nil
}
