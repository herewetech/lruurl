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
 * @file http_logic.go
 * @package main
 * @author Dr.NP <np@corp.herewetech.com>
 * @since 05/20/2019
 */

package main

import (
	"common"
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"

	"github.com/valyala/fasthttp"
)

func index(ctx *fasthttp.RequestCtx) {
	fmt.Fprint(ctx, "Hello lruurl\n")

	return
}

func clientSign(ctx *fasthttp.RequestCtx) {
	r := ctx.UserValue("_g").(*common.GlobalRuntime)
	claims := &common.JwtClaims{}
	claims.UserType = ctx.UserValue("client_type").(string)
	claims.ExpiresAt = time.Now().Add(time.Minute * 5).Unix()
	key := []byte(r.Config.GetString("jwt_key"))
	tkn := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := tkn.SignedString(key)
	if err != nil {
		fmt.Print(err.Error())
		ctx.Error("Sign JWT failed", fasthttp.StatusInternalServerError)
	} else {
		ctx.SetUserValue("_envelope_data", tokenString)
	}

	return
}

func clientInfo(ctx *fasthttp.RequestCtx) {
	ctx.SetUserValue("_envelope_data", ctx.UserValue("jwt_claims"))

	return
}

// HTTP CORS
func cors(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.Response.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	ctx.Response.Header.Set("Access-Control-Allow-Headers", "Content-Type")
	ctx.Response.Header.Set("Access-Control-Max-Age", "86400")

	return
}

// Logic routers
func svc(s *common.HTTPServer) {
	s.Router.GET("/", index)
	s.Router.GET("/client_sign/:client_type",
		common.HTTPEnvelope(
			common.HTTPGlobalRuntime(
				common.HTTPAuthorization(clientSign, "basic"),
				s.Runtime)))
	s.Router.GET("/client_info",
		common.HTTPEnvelope(
			common.HTTPGlobalRuntime(
				common.HTTPAuthorization(clientInfo, "jwt"),
				s.Runtime)))
	s.Router.OPTIONS("/*_all", cors)

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
