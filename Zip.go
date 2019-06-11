package main

import (
	"MimojaFirmwareToolkit/pkg/Common"
	"archive/zip"
	"bytes"
	"io/ioutil"
)

func Unzip(file MFTCommon.StorageEntry, data []byte) (map[string][]byte, error) {

	entries := make(map[string][]byte)

	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return entries, err
	}

	for _, f := range r.File {

		rc, err := f.Open()
		if err != nil {
			Bundle.Log.WithField("file", file).WithError(err).Errorf("Could not open inzip file: %v : %v", f.Name, err)
			return entries, err
		}
		defer rc.Close()

		if !f.FileInfo().IsDir() {

			fileBytes, err := ioutil.ReadAll(rc)
			if err != nil {
				Bundle.Log.WithField("file", file).WithError(err).Errorf("Could not read all bytes from zipped file: %v", err)
				return entries, err
			}

			entries[f.Name] = fileBytes
		}
	}
	return entries, nil
}
