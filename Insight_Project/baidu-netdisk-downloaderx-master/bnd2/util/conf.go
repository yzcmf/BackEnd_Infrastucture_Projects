package util

import (
	"path/filepath"

	"github.com/b3log/gulu"
)

const Ver = "2.0.0"

var SK = []byte("696D887C9AA0611B")
var UserAgent = "BND2/v" + Ver

const (
	ServerPort = 6804
	AriaPort   = 6805
)

var HomeDir, _ = gulu.OS.Home()
var BndDir = filepath.Join(HomeDir, ".bnd2")
