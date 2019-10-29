package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/Mimoja/MFT-Common"
	"io/ioutil"
	"path/filepath"
)

type EfiCapsule struct {
	HeaderSize                  uint32
	Flags                       uint32
	CapsuleImageSize            uint32
	SequenceNumber              uint32
	InstanceId                  [16]uint8
	OffsetToSplitInformation    uint32
	OffsetToCapsuleBody         uint32
	OffsetToOemDefinedHeader    uint32
	OffsetToAuthorInformation   uint32
	OffsetToRevisionInformation uint32
	OffsetToShortDescription    uint32
	OffsetToLongDescription     uint32
	OffsetToApplicableDevices   uint32
}

type EFI2Capsule struct {
	HeaderSize       uint32
	Flags            uint32
	CapsuleImageSize uint32
	FwImageOffset    uint16
	OemHdrOffset     uint16
}

func UnpackEFI1Capsule(file *MFTCommon.StorageEntry, data []byte) (map[string][]byte, error) {

	entries := make(map[string][]byte)
	fpath := filepath.Join(file.Path, "flashimage.bin")

	Bundle.Log.WithField("file", file).Info("Found Raw EFI gen 1 capsule")

	var capsule EfiCapsule

	reader := bytes.NewReader(data[16:])

	err := binary.Read(reader, binary.LittleEndian, &capsule)
	if err != nil {
		Bundle.Log.WithField("file", file).WithError(err).Errorf("Could not read Capsule!: ", err)
		return entries, err
	}

	Bundle.Log.WithField("file", file).Infof("Firmware starts at 0x%x\n", capsule.OffsetToCapsuleBody)

	if capsule.SequenceNumber > 0 || capsule.OffsetToSplitInformation > 0 {
		Bundle.Log.WithField("file", file).Errorf("Split Capsule. Unhandled!")
	}

	reader.Seek(int64(capsule.OffsetToCapsuleBody-16), 0)
	flashImage, err := ioutil.ReadAll(reader)
	if err != nil {
		Bundle.Log.WithField("file", file).WithError(err).Errorf("Could not read Image!: %v", err)
		return entries, err
	}
	entries[fpath] = flashImage

	return entries, nil

}
func UnpackEFI2Capsule(file *MFTCommon.StorageEntry, data []byte) (map[string][]byte, error) {
	entries := make(map[string][]byte)
	fpath := filepath.Join(file.Path+".capsule", "flashimage.bin")

	Bundle.Log.WithField("file", file).Info("Found EFI gen 2 capsule")
	var capsule EFI2Capsule

	reader := bytes.NewReader(data[16:])

	err := binary.Read(reader, binary.LittleEndian, &capsule)
	if err != nil {
		Bundle.Log.WithField("file", file).WithError(err).Errorf("Could not read Capsule!: ", err)
		return entries, err
	}
	Bundle.Log.WithField("file", file).Infof("Firmware starts at 0x%x\n", capsule.FwImageOffset)

	reader.Seek(int64(capsule.FwImageOffset-16), 0)
	flashImage, err := ioutil.ReadAll(reader)
	if err != nil {
		Bundle.Log.WithField("file", file).WithError(err).Errorf("Could not read Image!: %v", err)
		return entries, err
	}
	entries[fpath] = flashImage

	return entries, nil
}

func UnpackUnknown(file *MFTCommon.StorageEntry, data []byte) (map[string][]byte, error) {
	GUIDBytes := data[:16]

	entries := make(map[string][]byte)

	return entries, fmt.Errorf("Unknown CAP GUID %x\n", GUIDBytes)
}
