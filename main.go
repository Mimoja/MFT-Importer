package main

import (
	"MimojaFirmwareToolkit/pkg/Common"
	"encoding/json"
	"os"
)

var Bundle MFTCommon.AppBundle

const NumberOfWorker = 1

func worker(id int, file <-chan MFTCommon.DownloadEntry) {

	for true {
		entry := <-file
		Bundle.Log.WithField("file", entry).Infof("Handeling %s in Worker %d", entry.PackageID.GetID(), id)
		analyse(entry)
	}
}

func main() {

	Bundle = MFTCommon.Init("Importer")

	jsonEncoder = json.NewEncoder(os.Stdout)
	jsonEncoder.SetIndent("", "  ")

	setupYara()

	entries := make(chan MFTCommon.DownloadEntry, NumberOfWorker)
	for w := 1; w <= NumberOfWorker; w++ {
		go worker(w, entries)
	}

	Bundle.MessageQueue.DownloadedQueue.RegisterCallback("Importer", func(payload string) error {

		Bundle.Log.WithField("payload", payload).Debug("Got new Message!")
		var entry MFTCommon.DownloadEntry
		err := json.Unmarshal([]byte(payload), &entry)
		if err != nil {
			Bundle.Log.WithField("payload", payload).WithError(err).Error("Could not unmarshall json: %v", err)
		}

		//go analyse(entry)
		//analyse(entry)
		entries <- entry
		return nil
	})
	Bundle.Log.Infof("Starting up!")
	select {}
}
