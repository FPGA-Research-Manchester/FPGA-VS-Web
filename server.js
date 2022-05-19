"use strict"
const express = require("express")

// config
const listenPort = 5000

// setup
console.log("Starting VS Website")
const app = express()                       // create new web server
app.set("view engine", "ejs")               // setup ejs as template engine
app.use(require("./routes/index.js"))       // setup route handlers


// start serving requests
app.listen(listenPort, () => {
  console.log("Website is running on port " + listenPort)
})
