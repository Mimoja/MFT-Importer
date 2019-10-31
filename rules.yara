
rule ifd {
    strings:
        $ifdHeader  = {5a a5 f0 0f}
    condition:
        $ifdHeader at 0x0
        or $ifdHeader at 0x10
}

rule intel_bootguard {
    strings:
        $acbp = "__ACBP__" // BootPolicyManifest
        $keym = "__KEYM__" // Key
        $ibbs = "__IBBS__" // BootBlock
        $pmsg = "__PMSG__" // BootPolicySignature

    condition:
        any of them
}

rule efiString {
    strings:
        $EFIFilesystem     = {d954937a68044a4481ce0bf617d890df}
        $EFIFilesystemv2   = {78e58c8c3d8a1c4f9935896185c32dd3}
        $AppleBootVolume   = {adeead04ff61314db6ba64f8bf901f5a}
        $AppleBootVolumev2 = {8c1b00bd716a7b48a14f0c2a2dcf7a5d}
        $Intelv1           = {ffff3fad8bd2c4449f139ea98a97f9f0}
        $Intelv2           = {70cda1d6334b9449a6ea375f2ccc5437}
        $Sonyv1            = {5641494fd6ae644da537b8a5557bceec}
        $VariableStorage   = {8d2bf1ff96768b4ca9852747075b4f50}

    condition:
        $EFIFilesystem  at 16
        or $EFIFilesystemv2 at 16
        or $AppleBootVolume at 16
        or $AppleBootVolumev2 at 16
        or $Intelv1 at 16
        or $Intelv2 at 16
        or $Sonyv1 at 16
        or $VariableStorage at 16
}

rule unknownMarker {
    strings:
        $unknownGUID =   {00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
            33 33 33 33 33 33 33 33  33 33 33 33 33 33 33 33
            00 10 00 00 00 00 00 00  5f 46 56 48 ff 8e ff ff}
        $DMI = "$DMI"
        $GESA = "AMD!GESA"

    condition:
        $unknownGUID at 0x24000
        or $DMI at 0x1000
        or $GESA
}

rule efiCapsule {
    strings:
        $EFI1 = {BD86663B760D3040B70EB5519E2FC5A0}
        $EFI2 = {8BA63C4A2377FB48803D578CC1FEC44D}
        $UEFI = {B9829153B5AB9143B69AE3A943F72FCC}
        $AMIU = {90bbee140a89db43aed15d3c4588a418}
        $TOSH = {6270e03b511dd245832bf093257ed461}

        condition:
                $EFI1
                or $EFI2
                or $UEFI
                or $AMIU
                or $TOSH
}

rule ec {
    strings:
        $ITERevision = {00 24 52 65 76 69 73 69  6f 6e 3a 20 20 20 31 2e}
        $ITEHead = { 02 00 3? 00 00 00 00 00  02 10 3? 00 00 00 00 00
                     02 10 3? 00 00 00 00 00  02 10 3? 00 00 00 00 00
                     02 10 3? 00 00 00 00 00  02 10 3? 00 00 00 00 00}
    condition:
        $ITERevision at 0x1000 and
        $ITEHead at 0x0

}

rule asusString {
    strings:
        $ASUSBKP = {41535553424b50}

    condition:
        $ASUSBKP at 0x44000
}

rule amdHeader {
    strings:
        $AMDHeader = {aa 55 aa 55}
    condition:
        $AMDHeader at 0x20000
        or $AMDHeader at 0x820000
        or $AMDHeader at 0xC20000
        or $AMDHeader at 0xE20000
        or $AMDHeader at 0xF20000
        or uint32(0) == 0x55AA55AA
}

rule amdIMCHeader {
    strings:
        $IMCHeader = "_AMD_IMC_C"
    condition:
        $IMCHeader
}

rule bios {
         strings:
             $BiosHeader = {55 aa 55 aa}
         condition:
             $BiosHeader at 0x00
}

rule intelME {
        strings:
            $ME = {24 46 50 54}
        condition:
            $ME at 0x10
}

rule insyde {
    strings:
        $img = "$_IFLASH_BIOSIMG"
        $drv = "$_IFLASH_DRV_IMG"
        $ini = "$_IFLASH_INI_IMG"
        $ec  = "$_IFLASH_EC_IMG_"

    condition:
        all of them
}

rule archives {
	strings:

	   $BZIP                 = {42 5A}
	   $GZ                   = {1F 8B}
	   $RAR                  = {52 61 72 21 1A 07 00}
	   $TAR                  = {75 73 74 61 72}
       $XZ                   = {FD 37 7A 58 5A 00}
       $ZIP                  = {50 4B 03 04 (00|09|0a|0b|14|2d)}
       $7ZIP                 = {37 7A BC AF 27 1C}

	condition:
	    $ZIP
	    or $GZ at 0x00
        or $BZIP at 0x00
        or $XZ
        or $TAR at 257
        or $RAR
        or $7ZIP
}

rule windows_exe {
    strings:
        $mzHeader = {4d 5a}
    condition:
        $mzHeader at 0x0
}

rule innoSetup {
    strings:
        $INNO_VERSION_1_2_10  = {72 44 6c 50 74 53 30 32 87 65 56 78}
        $INNO_VERSION_4_0_0   = {72 44 6c 50 74 53 30 34 87 65 56 78}
        $INNO_VERSION_4_0_3   = {72 44 6c 50 74 53 30 35 87 65 56 78}
        $INNO_VERSION_4_0_10  = {72 44 6c 50 74 53 30 36 87 65 56 78}
        $INNO_VERSION_4_1_6   = {72 44 6c 50 74 53 30 37 87 65 56 78}
        $INNO_VERSION_5_1_5   = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a}
        $INNO_VERSION_5_1_5_2 = {6e 53 35 57 37 64 54 83 aa 1b 0f 6a}
        $INNO_TAG             = "Inno Setup"

    condition:
        any of them
}


rule heritage {
    strings:
        $phoenix = "Phoenix Technologies"
        $award = "Award Software"
        $ami = "American Megatrends"

    condition:
        $phoenix
        or $award
        or $ami
}
