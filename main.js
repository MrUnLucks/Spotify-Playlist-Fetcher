const express = require("express");
const request = require("request");
const crypto = require("crypto");
const cors = require("cors");
const querystring = require("querystring");
const cookieParser = require("cookie-parser");
const fs = require("fs");
require("dotenv").config();

const client_id = process.env.CLIENT_ID;
const client_secret = process.env.CLIENT_SECRET;
const redirect_uri = process.env.REDIRECT_URI;

const generateRandomString = (length) => {
  return crypto.randomBytes(60).toString("hex").slice(0, length);
};

const stateKey = "spotify_auth_state";
const PORT = 8888;

const app = express();

app
  .use(express.static(__dirname + "/public"))
  .use(cors())
  .use(cookieParser());

app.get("/login", function (req, res) {
  var state = generateRandomString(16);
  res.cookie(stateKey, state);

  // your application requests authorization
  var scope =
    "user-read-private user-read-email playlist-read-private playlist-read-collaborative playlist-modify-private playlist-modify-public user-read-playback-position user-top-read user-read-recently-played user-library-modify user-library-read";
  res.redirect(
    "https://accounts.spotify.com/authorize?" +
      querystring.stringify({
        response_type: "code",
        client_id: client_id,
        scope: scope,
        redirect_uri: redirect_uri,
        state: state,
      })
  );
});

const redirectError = (res, message) => {
  res.redirect(
    "/#" +
      querystring.stringify({
        error: message,
      })
  );
};

app.get("/callback", function (req, res) {
  // your application requests refresh and access tokens
  // after checking the state parameter

  var code = req.query.code || null;
  var state = req.query.state || null;
  var storedState = req.cookies ? req.cookies[stateKey] : null;

  if (state === null || state !== storedState) {
    return redirectError(res, "state_mismatch");
  }
  res.clearCookie(stateKey);
  var authOptions = {
    url: "https://accounts.spotify.com/api/token",
    form: {
      code: code,
      redirect_uri: redirect_uri,
      grant_type: "authorization_code",
    },
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      Authorization:
        "Basic " +
        new Buffer.from(client_id + ":" + client_secret).toString("base64"),
    },
    json: true,
  };

  request.post(authOptions, function (error, response, body) {
    if (error || response.statusCode !== 200) {
      return redirectError(res, "invalid_token");
    }

    var access_token = body.access_token,
      refresh_token = body.refresh_token;

    var options = {
      url: "https://api.spotify.com/v1/me/top/tracks?offset=10000&time_range=long_term&limit=45",
      headers: { Authorization: "Bearer " + access_token },
      json: true,
    };

    // use the access token to access the Spotify Web API
    request.get(options, function (error, response, body) {
      //   const toRet = body;
      //   delete toRet["items"];
      // console.log(body);
    });

    // we can also pass the token to the browser to make requests from there
    res.redirect(
      "/#" +
        querystring.stringify({
          access_token: access_token,
          refresh_token: refresh_token,
        })
    );
  });
});

app.get("/refresh_token", function (req, res) {
  var refresh_token = req.query.refresh_token;
  var authOptions = {
    url: "https://accounts.spotify.com/api/token",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      Authorization:
        "Basic " +
        new Buffer.from(client_id + ":" + client_secret).toString("base64"),
    },
    form: {
      grant_type: "refresh_token",
      refresh_token: refresh_token,
    },
    json: true,
  };

  request.post(authOptions, function (error, response, body) {
    if (!error && response.statusCode === 200) {
      var access_token = body.access_token,
        refresh_token = body.refresh_token;
      res.send({
        access_token: access_token,
        refresh_token: refresh_token,
      });
    }
  });
});

console.log(`Listening on ${PORT}`);
app.listen(PORT);
