"use strict"
const fs = require('fs');


// simple json based data store
class DataStore {
  constructor(datafile) {
    this.filename = datafile
    if (fs.existsSync(this.filename)) {
      this.data = JSON.parse(fs.readFileSync(this.filename))
      this.fresh = false
    } else {
      this.data = {}
      this.fresh = true
    } 
  }

  flush() {
    fs.writeFileSync(this.filename, JSON.stringify(this.data, null, 2))
  }

  flushAfter(job) {
    job(this.data)
    this.flush()
  }
}

module.exports = {DataStore}
