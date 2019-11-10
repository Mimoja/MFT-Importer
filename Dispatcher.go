package main

import (
	"encoding/json"
	"github.com/Mimoja/MFT-Common"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"
)

var jsonEncoder *json.Encoder

func analyse(entry MFTCommon.DownloadWrapper) MFTCommon.ImportEntry {

	Bundle.Log.WithField("file", entry).Infof("Dispatching %s", entry.PackageID.GetID())

	var ientry MFTCommon.ImportEntry

	if !Bundle.Config.App.Importer.ForceReimport && !entry.ForceReimport {
		found, err, oldIEntry := Bundle.DB.Exists("imports", entry.PackageID.GetID())
		if err == nil && found == true {
			data, err := oldIEntry.Source.MarshalJSON()
			if err != nil {
				Bundle.Log.WithError(err).Info("Could not get old entry from elastic: %v", err)
			} else {
				//s := string(downloadFileContent)
				//fmt.Println(s)
				err = json.Unmarshal(data, &ientry)
				if err != nil {
					Bundle.Log.WithError(err).WithField("payload", string(data)).Warnf("Could unmarshall old entry from elastic: %v", err)
				}
				updateRequired := true
				if ientry.ImportDataDefinition != "" {
					updateRequired, err = MFTCommon.DataDefinitionUpgradeRequired(MFTCommon.CurrentImportDataDefinition, ientry.ImportDataDefinition)
					if err != nil {
						Bundle.Log.WithField("file", entry).WithError(err).Warnf("Could not parse version fils: %s %v", ientry.ImportDataDefinition, err)
					}
				}

				if ientry.Success && !updateRequired {
					Bundle.Log.WithField("file", entry).Info("Skipping Import: ", entry.DownloadPath)
					sendImportEntry(ientry)
					return ientry
				}

				if updateRequired {
					Bundle.Log.WithField("file", entry).Info("Import already exists but requires upgrade")
				}

				if !ientry.Success {
					Bundle.Log.WithField("file", entry).Info("Import already exists but nothing was found")
				}

			}
		}
	}

	ientry = MFTCommon.ImportEntry{
		ImportDataDefinition: MFTCommon.CurrentImportDataDefinition,
		MetaData:             entry.DownloadEntry,
		Success:              false,
	}

	downloadFile := MFTCommon.StorageEntry{
		ID:        entry.PackageID,
		Path:      entry.DownloadPath,
		PackageID: entry.PackageID,
		Tags:      []string{"DOWNLOAD"},
	}

	object, err := Bundle.Storage.GetFile(downloadFile.PackageID.GetID())
	if err != nil {
		Bundle.Log.WithField("file", downloadFile).WithError(err).Error("Could not fetch file from storage: %v\n", err)
		return ientry
	}
	defer object.Close()

	downloadFileContent, err := ioutil.ReadAll(object)
	if err != nil {
		Bundle.Log.WithError(err).Error("Could not read from storage: %v\n", err)
		return ientry
	}

	ientry, err = detect(ientry, &downloadFile, downloadFileContent)
	if err != nil {
		Bundle.Log.WithError(err).WithField("file", downloadFile).Error("Import failed: %v\n", err)
		return ientry
	}

	ientry.Contents = append([]MFTCommon.StorageEntry{downloadFile}, ientry.Contents...)
	ientry.ImportTime = time.Now().Format("2006-01-02T15:04:05Z07:00")

	sendImportEntry(ientry)

	Bundle.Log.WithField("file", entry).Info("Finished analysis")

	return ientry
}

func sendImportEntry(ientry MFTCommon.ImportEntry) {

	for _, storageEntryElement := range ientry.Contents {
		for _, tag := range storageEntryElement.Tags {

			switch tag {
			case "FLASHIMAGE":
				Bundle.Log.WithField("file", ientry).WithField("entry", storageEntryElement).Info("Sending flashimage")

				flashImage := MFTCommon.FlashImage{
					MetaData: ientry.MetaData,
					ID:       storageEntryElement.ID,
					Tags:     storageEntryElement.Tags,
				}

				err := Bundle.MessageQueue.FlashImagesQueue.MarshalAndSend(flashImage)
				if err != nil {
					Bundle.Log.WithError(err).Error("Could not send entry to flashimage Queue: %v \n", err)
				}

				indexType := "flashimage"
				id := flashImage.ID.GetID()
				Bundle.DB.StoreElement("flashimages", &indexType, flashImage, &id)

				ientry.Success = true

			case "INTELME":
				Bundle.Log.WithField("file", ientry).WithField("entry", storageEntryElement).Info("Sending meimage")

				err := Bundle.MessageQueue.MEImagesQueue.MarshalAndSend(storageEntryElement)
				if err != nil {
					Bundle.Log.WithError(err).Error("Could not send entry to flashimage Queue: %v \n", err)
				}
				ientry.Success = true
			}

		}
		// Send everything threw cert searcher
		//Bundle.MessageQueue.ExtractedQueue.MarshalAndSend(storageEntryElement)
	}
	if !ientry.Success {
		Bundle.Log.WithField("file", ientry).Warnf("Nothing found inside of: %s", ientry.MetaData.PackageID.GetID())
	}

	id := ientry.MetaData.PackageID.GetID()
	Bundle.DB.StoreElement("imports", nil, ientry, &id)

}

func dispatchChild(entry MFTCommon.ImportEntry, file *MFTCommon.StorageEntry, data []byte) (MFTCommon.ImportEntry, error) {
	Bundle.Log.WithField("file", file).Infof("Dispatching Child: %s \n", file.ID.GetID())
	return detect(entry, file, data)
}

func detect(entry MFTCommon.ImportEntry, storageEntry *MFTCommon.StorageEntry, data []byte) (MFTCommon.ImportEntry, error) {

	extension := filepath.Ext(storageEntry.Path)
	extension = strings.ToLower(extension)

	Bundle.Log.WithField("storageEntry", storageEntry).Info("Extension is " + extension)

	switch extension {
	case ".exe":
		//TODO run special detection!

	case ".jpg":
		fallthrough
	case ".jpeg":
		fallthrough
	case ".png":
		storageEntry.Tags = append(storageEntry.Tags, "IMAGE")
		fallthrough
	case ".bat":
		fallthrough
	case ".txt":
		fallthrough
	case ".inf":
		return entry, nil

	case ".efi":
		storageEntry.Tags = append(storageEntry.Tags, "EFI_EXECUTABLE")

	case ".bin":
		fallthrough
	case ".fd":
		fallthrough
	case ".fd1":
		fallthrough
	case ".fd2":
		fallthrough
	case ".rom":
		storageEntry.Tags = append(storageEntry.Tags, "FLASHIMAGE_BY_FILEEXTENSION")
	}

	// scan for known magic bytes
	files := detectMagic(storageEntry, data)
	for key, value := range files {
		Bundle.Log.WithField("storageEntry", storageEntry).Info("Adding ", key, " to children")

		sentry := MFTCommon.StorageEntry{
			ID:        MFTCommon.GenerateID(value),
			PackageID: entry.MetaData.PackageID,
			Path:      key,
			Tags:      nil,
		}

		err := Bundle.Storage.StoreBytes(value, sentry.ID.GetID())
		if err != nil {
			Bundle.Log.WithError(err).WithField("storageEntry", storageEntry).Error("Could not store entry: %v\n", err)
			return entry, err
		}

		entry, err = dispatchChild(entry, &sentry, value)
		if err != nil {
			Bundle.Log.WithError(err).WithField("storageEntry", storageEntry).Error("Could not handle children: ", err)
			return entry, err
		}
		entry.Contents = append(entry.Contents, sentry)
	}

	return entry, nil
}
