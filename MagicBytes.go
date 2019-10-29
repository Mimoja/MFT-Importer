package main

import (
	"MimojaFirmwareToolkit/pkg/Common"
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/gen2brain/go-unarr"
	"github.com/hillu/go-yara"
	"io"
	"log"
	"os"
	"path"
	"strings"
)

var yaraRules *yara.Rules

func setupYara() {
	c, err := yara.NewCompiler()
	if err != nil {
		panic("Could not create yara compiler")
	}

	file, err := os.Open("rules.yara")
	if err != nil {
		log.Fatalf("Could not load rules: %v", err)
	}

	c.AddFile(file, "test")

	r, err := c.GetRules()
	if err != nil {
		log.Fatalf("Failed to compile rules: %s", err)
	}
	yaraRules = r
}

func detectMagic(entry *MFTCommon.StorageEntry, data []byte) map[string][]byte {

	entries := make(map[string][]byte)

	Bundle.Log.WithField("file", entry).Info("Searching for Magic Bytes")

	matches, err := yaraRules.ScanMem(data, 0, 0)
	if err != nil {
		Bundle.Log.WithField("file", entry).WithError(err).Errorf("could not scan with yara %v\n", err)
		return entries
	}

	if len(matches) == 0 {
		Bundle.Log.WithField("file", entry).Warn("Could not find any matches!")
	}

	for _, match := range matches {

		for _, m := range match.Strings {
			Bundle.Log.WithField("file", entry).Infof("Found: %s : %s at 0x%X", match.Rule, m.Name[1:], m.Offset)

			name := strings.ToUpper(m.Name[1:])
			rule := strings.ToUpper(match.Rule)
			entry.Tags = appendTagIfMissing(entry.Tags, "YARA_RULE_"+rule+"_"+name)
		}

		switch match.Rule {
		case "ifd":
			entry.Tags = appendTagIfMissing(entry.Tags, "FLASHIMAGE")
			entry.Tags = appendTagIfMissing(entry.Tags, "INTEL")
		case "efiString":
			entry.Tags = appendTagIfMissing(entry.Tags, "FLASHIMAGE")
			entry.Tags = appendTagIfMissing(entry.Tags, "EFI")
		case "amdHeader":
			entry.Tags = appendTagIfMissing(entry.Tags, "FLASHIMAGE")
			entry.Tags = appendTagIfMissing(entry.Tags, "AMD")
		case "asusString":
			entry.Tags = appendTagIfMissing(entry.Tags, "FLASHIMAGE")
			entry.Tags = appendTagIfMissing(entry.Tags, "ASUS")
		case "bios":
			entry.Tags = appendTagIfMissing(entry.Tags, "FLASHIMAGE")
			entry.Tags = appendTagIfMissing(entry.Tags, "BIOS")
		case "intelME":
			fmt.Printf("Found ME Image!\n")
			entry.Tags = appendTagIfMissing(entry.Tags, "INTELME")
		case "insyde":
			entry.Tags = appendTagIfMissing(entry.Tags, "INSYDE")
			m := match.Strings[0]
			fmt.Printf("Found image at offset: 0x%x\n", match.Strings[0].Offset)
			headerLength := uint64(len(m.Data))
			byteslice := data[m.Offset+headerLength+4 : m.Offset+headerLength+8]
			length := uint64(binary.LittleEndian.Uint32(byteslice))
			result := data[m.Offset+headerLength+8 : m.Offset+headerLength+8+length]
			fpath := path.Join(entry.Path, "flashimage.bin")
			fmt.Printf("Extracted: 0x%x bytes from insyde image\n", length)
			entries[fpath] = result
		case "ec":
			if match.Strings[1].Name == "$ITEHead" {
				Bundle.Log.WithField("file", entry).Infof("Found image at offset: 0x%x\n", match.Strings[0].Offset)
				entry.Tags = appendTagIfMissing(entry.Tags, "ITC")
				result := data[0x10000:]
				fpath := path.Join(entry.Path, "bios.bin")
				Bundle.Log.WithField("file", entry).Infof("Extracted: 0x%x bytes from ITE image\n", len(result))
				entries[fpath] = result
				break
			}
		case "unknownMarker":
			for _, m := range match.Strings {
				Bundle.Log.WithField("file", entry).Info("Found guessed Flashimage marker!\n")
				entry.Tags = appendTagIfMissing(entry.Tags, "FLASHIMAGE")
				entry.Tags = appendTagIfMissing(entry.Tags, "UNKNOWN")
				name := strings.ToUpper(m.Name[1:])
				entry.Tags = appendTagIfMissing(entry.Tags, "UNKNOWN_"+name)
			}
		case "heritage":
			for _, m := range match.Strings {
				name := strings.ToUpper(m.Name[1:])
				Bundle.Log.WithField("file", entry).Info("Found copyright string for : ", name)
				entry.Tags = appendTagIfMissing(entry.Tags, "COPYRIGHT_"+name)
			}
		case "efiCapsule":
			// ignore efi capules, inside a flashimage
			if containsTag(entry.Tags, "FLASHIMAGE") {
				break
			}

			newEntries := make(map[string][]byte)

			for _, m := range match.Strings {
				name := m.Name[1:]
				efiData := data[m.Offset:]

				switch name {
				case "EFI1":
					newEntries, err = UnpackEFI1Capsule(entry, efiData)
					break
				case "EFI2":
					newEntries, err = UnpackEFI2Capsule(entry, efiData)
					break
				default:
					Bundle.Log.WithField("file", entry).Error("Unhandled GUID: ", name)
					newEntries, err = UnpackUnknown(entry, efiData)

					break
				}

				if err != nil {
					Bundle.Log.WithField("file", entry).WithError(err).Error("Error while extracting Capsule: ", err)
					continue
				}
				for key, value := range newEntries {
					entries[key] = value
				}
				break
			}

			break

		case "archives":
			skiplist := make(map[uint64]string)
			for _, m := range match.Strings {
				nameString := m.Name[1:]
				switch nameString {
				case "ZIP":
					if skiplist[m.Offset] == nameString {
						continue
					}

					// Find footer
					zipFooter := []byte{0x50, 0x4B, 0x05, 0x06}
					end := bytes.Index(data[m.Offset:], zipFooter)
					if end == -1 {
						err = fmt.Errorf("ZIP Footer not found")
						Bundle.Log.WithError(err).WithField("file", entry).Error("Could not unzip file: ", err)
						continue
					}

					Bundle.Log.WithField("file", entry).Infof("Found Zip footer at 0x%08X", end)

					// Skip all other ZIP entries before the next DIRECTORY_END
					for _, other := range match.Strings {
						if other.Name[1:] == "ZIP" && other.Offset < uint64(end)+m.Offset {
							skiplist[other.Offset] = nameString
						}
					}

					zipData := data[m.Offset : uint64(end)+m.Offset+21+1]

					zipFiles, err := Unzip(*entry, zipData)

					if err != nil {
						Bundle.Log.WithError(err).WithField("file", entry).Errorf("Could not unzip file: %v", err)
						continue
					}

					for key, value := range zipFiles {
						fpath := path.Join(entry.Path, key)
						entries[fpath] = value
					}

				case "7ZIP":
					fallthrough
				case "RAR":
					a, err := unarr.NewArchiveFromMemory(data[m.Offset:])
					if err != nil {
						Bundle.Log.WithError(err).WithField("file", entry).Errorf("Could not unpack %s file: %v : %", nameString, err)
						continue
					}

					for {
						err := a.Entry()
						if err != nil {
							if err == io.EOF {
								break
							} else {
								Bundle.Log.WithError(err).WithField("file", entry).Errorf("Unexpected Error with %s: %v", nameString, err)
								break
							}
						}

						data, err := a.ReadAll()
						if err != nil {
							Bundle.Log.WithError(err).WithField("file", entry).Errorf("Could not extract file from %s archive:  %v", nameString, err)
							continue
						}

						fpath := path.Join(entry.Path, a.Name())
						entries[fpath] = data
					}
					a.Close()
				default:
					Bundle.Log.WithField("file", entry).Errorf("Unhandled RULE: %s : %s at 0x%X", match.Rule, m.Name[1:], m.Offset)
				}
			}
		default:
			for _, m := range match.Strings {
				Bundle.Log.WithField("file", entry).Errorf("Unhandled RULE: %s : %s at 0x%X", match.Rule, m.Name[1:], m.Offset)
			}
			continue
		}
	}
	return entries
}
func containsTag(slice []string, i string) bool {
	for _, ele := range slice {
		if ele == i {
			return true
		}
	}
	return false
}
func appendTagIfMissing(slice []string, i string) []string {
	if !containsTag(slice, i) {
		return append(slice, i)
	}
	return slice
}
