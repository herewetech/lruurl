/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 HereweTech Co.LTD
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file lruurl.go
 * @package main
 * @author Dr.NP <np@corp.herewetech.com>
 * @since 05/20/2019
 */

package main

import (
	"common"
)

const (
	// DefaultHTTPListenAddr : String value of default HTTP server address
	DefaultHTTPListenAddr string = "127.0.0.1:7788"

	// DefaultLocalStoragePath : String value of default storage path locally
	DefaultLocalStoragePath string = "/var/lib/lrrurl"
)

var (
	g = common.NewRuntime("lruurl")
	s = common.NewHTTPServer(g)
)

func main() {
	g.Config.SetDefault("HTTP_Listen_Address", DefaultHTTPListenAddr)
	g.Config.SetDefault("Storage_Local_Path", DefaultLocalStoragePath)
	svc(s)
	s.Start()
	g.Wait()

	return
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
