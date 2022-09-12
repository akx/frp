// Copyright 2020 guylewin, guy@lewin.co.il
// Copyright 2022 Aarni Koskela
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"fmt"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/golang-jwt/jwt/v4"
	"time"
)

type JwtClientConfig struct {
	// JwtToken specifies the JWT token to send to the server.
	JwtToken string `ini:"jwt_token" json:"jwt_token"`
}

func getDefaultJwtClientConf() JwtClientConfig {
	return JwtClientConfig{
		JwtToken: "",
	}
}

type JwtServerConfig struct {
	// JwtAlgorithm specifies the expected signing algorithm for JWT tokens received from clients.
	JwtAlgorithm string `ini:"jwt_algorithm" json:"jwt_algorithm"`
	// JwtKey specifies the key used to verify JWT tokens received from clients.
	JwtKey string `ini:"jwt_key" json:"jwt_key"`
	// JwtIssuer specifies the issuer of the JWT token. If not set, the iss claim is not verified.
	JwtIssuer string `ini:"jwt_issuer" json:"jwt_issuer"`
	// JwtAudience specifies the audience of the JWT token. If not set, the aud claim is not verified.
	JwtAudience string `ini:"jwt_audience" json:"jwt_audience"`
	// JwtSkipExpiryCheck specifies whether to skip checking if the JWT token is expired.
	JwtSkipExpiryCheck bool `ini:"jwt_skip_expiry_check" json:"jwt_skip_expiry_check"`
	// JwtSkipNotBeforeCheck specifies whether to skip checking if the JWT token is
	// not valid yet.
	JwtSkipNotBeforeCheck bool `ini:"jwt_skip_not_before_check" json:"jwt_skip_not_before_check"`
	// JwtLeeway specifies the leeway to use in seconds when checking the exp and nbf claims.
	JwtLeeway int64 `ini:"jwt_leeway" json:"jwt_leeway"`
	// JwtLockJtiToRunID specifies whether to lock the jti claim to the run ID of the client.
	// If set, the jti claim must be set in the JWT token, and attempts for a different client
	// to use the same JTI will be rejected.
	JwtLockJtiToRunID bool `ini:"jwt_lock_jti_to_run_id" json:"jwt_lock_jti_to_run_id"`
}

func getDefaultJwtServerConf() JwtServerConfig {
	return JwtServerConfig{
		JwtAlgorithm:          "HS256",
		JwtKey:                "",
		JwtIssuer:             "",
		JwtAudience:           "",
		JwtSkipExpiryCheck:    false,
		JwtSkipNotBeforeCheck: false,
		JwtLeeway:             0,
	}
}

type JwtAuthProvider struct {
	BaseConfig
	token string
}

func NewJwtAuthSetter(baseCfg BaseConfig, cfg JwtClientConfig) *JwtAuthProvider {
	return &JwtAuthProvider{
		BaseConfig: baseCfg,
		token:      cfg.JwtToken,
	}
}

func (auth *JwtAuthProvider) generateAccessToken() (accessToken string, err error) {
	if auth.token == "" {
		return "", fmt.Errorf("no JWT token configured")
	}
	return auth.token, nil
}

func (auth *JwtAuthProvider) SetLogin(loginMsg *msg.Login) (err error) {
	loginMsg.PrivilegeKey, err = auth.generateAccessToken()
	return err
}

func (auth *JwtAuthProvider) SetPing(pingMsg *msg.Ping) (err error) {
	if !auth.AuthenticateHeartBeats {
		return nil
	}

	pingMsg.PrivilegeKey, err = auth.generateAccessToken()
	return err
}

func (auth *JwtAuthProvider) SetNewWorkConn(newWorkConnMsg *msg.NewWorkConn) (err error) {
	if !auth.AuthenticateNewWorkConns {
		return nil
	}

	newWorkConnMsg.PrivilegeKey, err = auth.generateAccessToken()
	return err
}

type JwtAuthConsumer struct {
	BaseConfig
	conf          JwtServerConfig
	jtiToRunIdMap map[string]string
}

func NewJwtAuthVerifier(baseCfg BaseConfig, cfg JwtServerConfig) *JwtAuthConsumer {
	return &JwtAuthConsumer{
		BaseConfig:    baseCfg,
		conf:          cfg,
		jtiToRunIdMap: make(map[string]string),
	}
}

func (auth *JwtAuthConsumer) verifyJwtToken(jwtToken string) (tok *jwt.Token, err error) {
	token, err := jwt.Parse(
		jwtToken,
		func(token *jwt.Token) (interface{}, error) {
			return []byte(auth.conf.JwtKey), nil
		},
		jwt.WithoutClaimsValidation(),                          // We will validate the claims ourselves
		jwt.WithValidMethods([]string{auth.conf.JwtAlgorithm}), // Only allow the specified algorithm
	)

	if err != nil {
		return nil, fmt.Errorf("invalid JWT token: %v", err)
	}

	claims := token.Claims.(jwt.MapClaims)
	if auth.conf.JwtIssuer != "" && !claims.VerifyIssuer(auth.conf.JwtIssuer, true) {
		return nil, fmt.Errorf("invalid JWT issuer: %s", claims["iss"])
	}
	if auth.conf.JwtAudience != "" && !claims.VerifyAudience(auth.conf.JwtAudience, true) {
		return nil, fmt.Errorf("invalid JWT audience: %s", claims["aud"])
	}
	now := time.Now().Unix()
	leeway := auth.conf.JwtLeeway
	if !auth.conf.JwtSkipExpiryCheck && !claims.VerifyExpiresAt(now+leeway, true) {
		return fmt.Errorf("JWT token expired")
	}
	if !auth.conf.JwtSkipNotBeforeCheck && !claims.VerifyNotBefore(now-leeway, true) {
		return nil, fmt.Errorf("JWT token not valid yet")
	}
	return tok, nil
}

func (auth *JwtAuthConsumer) VerifyLogin(loginMsg *msg.Login) (err error) {
	token, err := auth.verifyJwtToken(loginMsg.PrivilegeKey)
	if err != nil {
		return fmt.Errorf("invalid JWT token in login: %v", err)
	}
	if auth.conf.JwtLockJtiToRunID {
		claims := token.Claims.(jwt.MapClaims)
		jti := claims["jti"]
		if jti == nil {
			return fmt.Errorf("JWT token does not contain a jti claim")
		}
		if auth.jtiToRunIdMap[jti.(string)] != "" {
			return fmt.Errorf("JWT token jti already in use")
		}
		auth.jtiToRunIdMap[jti.(string)] = loginMsg.RunID
	}
	return nil
}

func (auth *JwtAuthConsumer) VerifyPing(pingMsg *msg.Ping) (err error) {
	if !auth.AuthenticateHeartBeats {
		return nil
	}
	_, err = auth.verifyJwtToken(pingMsg.PrivilegeKey)
	if err != nil {
		return fmt.Errorf("invalid JWT token in ping: %v", err)
	}
	return nil
}

func (auth *JwtAuthConsumer) VerifyNewWorkConn(newWorkConnMsg *msg.NewWorkConn) (err error) {
	if !auth.AuthenticateNewWorkConns {
		return nil
	}
	_, err = auth.verifyJwtToken(newWorkConnMsg.PrivilegeKey)
	if err != nil {
		return fmt.Errorf("invalid JWT token in work connection: %v", err)
	}
	return nil
}
