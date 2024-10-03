const express = require("express");
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
var access_token;
var songs = [];
async function fetchWebApi(endpoint, method, body) {
  const res = await fetch(`https://api.spotify.com/${endpoint}`, {
    headers: {
      Authorization: `Bearer ${access_token}`,
    },
    method,
    body: JSON.stringify(body),
  });
  return await res.json();
}

async function createPlaylist(tracksUri) {
  const { id: user_id } = await fetchWebApi("v1/me", "GET");

  const playlist = await fetchWebApi(`v1/users/${user_id}/playlists`, "POST", {
    name: "Test playlist",
    description: "Playlist created automatically",
    public: false,
  });

  await fetchWebApi(
    `v1/playlists/${playlist.id}/tracks?uris=${tracksUri.join(",")}`,
    "POST"
  );

  return playlist;
}

async function getSongs() {
  const data = fs.readFileSync("./songs.txt", "utf8");
  const regexTimestamp =
    /\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2})?(?:Z|[+-]\d{2}:\d{2})?/g;
  let rawSongs = data
    .replace(/\r/g, "")
    .replace(regexTimestamp, "")
    .split("\n");
  songs = await fetchSongs(rawSongs);
}

async function fetchSongs(songs) {
  return await Promise.all(
    songs.map(async (el) => {
      const song = await fetchWebApi(`v1/search?q=${el}&type=track&limit=1`);
      return song.tracks.items[0]?.uri;
    })
  ).then((results) => results.filter(Boolean));
}

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

  fetch(authOptions.url, {
    method: "POST",
    headers: authOptions.headers,
    body: new URLSearchParams(authOptions.form),
  })
    .then((response) => {
      if (!response.ok) {
        return redirectError(res, "invalid_token");
      }
      return response.json();
    })
    .then(async (body) => {
      access_token = body.access_token;
      refresh_token = body.refresh_token;

      await getSongs();
      createPlaylist(songs);

      // we can also pass the token to the browser to make requests from there
      res.redirect(
        "/#" +
          querystring.stringify({
            access_token: access_token,
            refresh_token: refresh_token,
          })
      );
    })
    .catch((error) => redirectError(res, "invalid_token"));
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

  fetch(authOptions.url, {
    headers: authOptions.headers,
    body: new URLSearchParams(authOptions.form),
  })
    .then(() => {
      res.send({
        access_token: body.access_token,
        refresh_token: body.refresh_token,
      });
    })
    .catch((error) => redirectError(res, "invalid_refresh"));
});

console.log(`Listening on ${PORT}`);
app.listen(PORT);
