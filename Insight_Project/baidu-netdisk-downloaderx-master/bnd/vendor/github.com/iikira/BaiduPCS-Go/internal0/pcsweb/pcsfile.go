package pcsweb

import (
	"github.com/iikira/BaiduPCS-Go/internal0/pcsconfig"
	"io"
	"net/http"
)

func fileList(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	fpath := r.Form.Get("path")
	dataReadCloser, err := pcsconfig.Config.ActiveUserBaiduPCS().PrepareFilesDirectoriesList(fpath)
	if err != nil {
		w.Write((&ErrInfo{
			ErrroCode: 1,
			ErrorMsg:  err.Error(),
		}).JSON())
		return
	}

	defer dataReadCloser.Close()
	io.Copy(w, dataReadCloser)
}
