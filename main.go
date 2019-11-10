package main

import (
	"github.com/Mimoja/MFT-Common"
	"encoding/json"
	"os"
)

var Bundle MFTCommon.AppBundle

func main() {

	Bundle = MFTCommon.Init("Importer")

	jsonEncoder = json.NewEncoder(os.Stdout)
	jsonEncoder.SetIndent("", "  ")

	setupYara()


	Bundle.MessageQueue.DownloadedQueue.RegisterCallback("Importer", func(payload string) error {

		Bundle.Log.WithField("payload", payload).Debug("Got new Message!")
		var entry MFTCommon.DownloadEntry
		err := json.Unmarshal([]byte(payload), &entry)
		if err != nil {
			Bundle.Log.WithField("payload", payload).WithError(err).Error("Could not unmarshall json: %v", err)
		}

		Bundle.Log.WithField("file", entry).Infof("Handeling %s in Worker %d", entry.PackageID.GetID(), id)
		analyse(entry)
		return nil
	})
	Bundle.Log.Infof("Starting up!")
	select {}
}
