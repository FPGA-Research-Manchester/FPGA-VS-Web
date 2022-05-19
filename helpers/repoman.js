"use strict"
const fs = require("fs")

const {DataStore} = require("./datastore")
const scanner     = require("./virusscanner")


// === repository of bitstreams ===
class BitstreamStore {
  constructor(path) {
    this.path = path

    // handle folder
    if (!fs.existsSync(this.path))
      fs.mkdirSync(this.path)
    this._json = new DataStore(path + "/repo.json")

    // init if needed
    if (this._json.fresh)
      this.bitdata = []

    // load each bitstream ["path"]
    this.bits = this.bitdata.map(data => new Bitstream(this.path + "/" + data.path))
  }

  // create new bit in place
  newBit(path, name, file, key, date = new Date()) {
    let bitstream = new Bitstream(this.path + "/" + path, name, file, key, date)
    this.bitdata.push({path})
    this._json.flush()
    this.bits.push(bitstream)
    return bitstream
  }
  
  // add bit to store
  addBit(path, bit) {
    this.bitdata.push({path})
    this._json.flush()
    this.bits.push(bit)
  }

  // get bit paths
  getBits() {
    return this.bitdata.map(bit => bit.path)
  }

  // get a bit
  getBit(path) {
    return this.bits.find(bit => (this.path + "/" + path) == bit.path)
  }
  
  // get a bit
  getBitByKey(key) {
    return this.bits.find(bit => key == bit.key)
  }

  // json read write funcs
  setJson(key, value) { this._json.flushAfter(d => d[key] = value) }
  getJson(key)        { return this._json.data[key] }

  // first class json vars
  get bitdata()     { return this.getJson("bitdata") }
  set bitdata(data) { this.setJson("bitdata", data)  }
}




// === a bitstream in the repo, contains many jobs ===
class Bitstream {
  constructor(path, name, file, key, ispublic=false, date = new Date()) {

    // handle filesystem
    this.path = path
    if (!fs.existsSync(this.path))
      fs.mkdirSync(this.path)
    this._json = new DataStore(path + "/bitstream.json")

    // init metadata
    if (this._json.fresh) {
      this.name = name
      this.file = file
      this.key  = key
      this.ispublic = ispublic
      this.date = date
      this.jobdata = []
    }

    // load jobs [{"type": "<type>", "path": "path"}]
    this.jobs = this.jobdata.map(data => {
      switch (data.job_type) {
        case "BitPNGJob": return new BitPNGJob(this.path + "/" + data.path)
        case "CheckShellJob": return new CheckShellJob(this.path + "/" + data.path)
        case "JSONConvertJob": return new JSONConvertJob(this.path + "/" + data.path)
        case "FASMConvertJob": return new FASMConvertJob(this.path + "/" + data.path)
        case "VirusScanJob": return new VirusScanJob(this.path + "/" + data.path)
      }
      throw new Error("No such job type: " + data.job_type)
    })
  }

  // add existing job object to bitstream
  addJob(path, job) {
    this.jobdata.push({path, job_type: job.job_type})
    this._json.flush()
    this.jobs.push(job)
    return job
  }

  // get job paths
  getJobs() {
    return this.jobdata
  }

  // get a job
  getJob(path) {
    return this.jobs.find(job => (this.path + "/" + path) == job.path)
  }

  // json read write funcs
  setJson(key, value) { this._json.flushAfter(d => d[key] = value) }
  getJson(key)        { return this._json.data[key] }

  // first class json vars
  get name()     { return this.getJson("name") }
  set name(name) { this.setJson("name", name)  }
  get key()      { return this.getJson("key")  }
  set key(key)   { this.setJson("key", key)    }
  get ispublic()         { return this.getJson("ispublic")    }
  set ispublic(ispublic) { this.setJson("ispublic", ispublic) }
  get file()     { return this.getJson("file") }
  set file(file) { this.setJson("file", file)  }
  get date()     { return new Date(this.getJson("date")) }
  set date(date) { this.setJson("date", date.toJSON())   }
  get jobdata()     { return this.getJson("jobdata")}
  set jobdata(data) { this.setJson("jobdata", data)  }

  // get full path of bitstream
  fullPath()     { return this.path + "/" + this.file }
}




// === base class of a job ===
const validJobStates = ["waiting", "running", "done", "error"]
class BitJob {
  constructor(path, bitstream, state = "waiting") {

    // handle filesystem
    this.path = path
    if (!fs.existsSync(this.path))
      fs.mkdirSync(this.path)
    this._json = new DataStore(path + "/job.json")

    // init job data
    if (this._json.fresh) {
      this.bitstream = bitstream
      this.state = state
      this.create_date = new Date()
    } else {
      // any jobs which were running are now dead
      if (this.state == "running" || this.state == "waiting") {
        this.state = "error"
        this.end_date = new Date()
      }
    }
  }
  
  // watches the run() call and updates state based on outcome
  host(cb) {
    this.state = "running"
    this.start_date = new Date()
    this.run((err) => {
      this.end_date = new Date()
      if (err) {
        this.state = "error"
        return cb(err)
      } else {
        this.state = "done"
        return cb()
      }
    })
  }
  
  // pretty print job status
  job2str(job) {
    if (job.state == "waiting")
      return `[Job: ${this.path} Waiting (${job.file})]`
    else if (job.state == "running") 
      return `[Job: ${this.path} Running since ${job.stime} (${job.file})]`
    else if (job.state == "done")
      return `[Job: ${this.path} Done, score is ${job.results.score} (${job.file})]`
    else if (job.state == "error")
      return `[Job: ${this.path} Errors encountered, (${job.file})]`
    else
      return `[Job: ${this.path} Unknown state: ${job.state} (${job.file})]`
  }

  // json read write funcs
  setJson(key, value) { this._json.flushAfter(d => d[key] = value) }
  getJson(key)        { return this._json.data[key] }

  // first class json vars
  get type()            { return this.getJson("type")                   }
  set type(type)        { this.setJson("type", type)                    }
  get bitstream()       { return this.getJson("bitstream")              }
  set bitstream(bs)     { this.setJson("bitstream", bs)                 }
  get create_date()     { return new Date(this.getJson("create_date"))  }
  set create_date(date) { this.setJson("create_date", date.toJSON())    }
  get start_date()      { return new Date(this.getJson("start_date"))   }
  set start_date(date)  { this.setJson("start_date", date.toJSON())     }
  get end_date()        { return new Date(this.getJson("end_date"))     }
  set end_date(date)    { this.setJson("end_date", date.toJSON())       }

  // filter state var to valid states
  get state()    { return this.getJson("state") }
  set state(state) {
    if (!validJobStates.includes(state))
      throw new Error("Invalid job state: " + state)
    this.setJson("state", state)
  }
}



// ============ job data ===================

// gets a PNG of the LUT and FF usage of a bitstream
class BitPNGJob extends BitJob {
  constructor(path, bitstream) {
    super(path, bitstream)
    this.job_type = "BitPNGJob"
  }
  
  getLog() {
    return this.path + "/log.txt"
  }

  // get png file
  getPNG() {
    return this.path + "/util.png"
  }
  
  // run png generator
  run(cb) {
    scanner.runbit2png(this.bitstream, this.getPNG(), this.getLog(), cb)
  }
}





// convert bitstream to json
class JSONConvertJob extends BitJob {

  constructor(path, bitstream) {
    super(path, bitstream)
    this.job_type = "JSONConvertJob"
  }

  getLog()      { return this.path + "/log.txt" }
  getJSON()     { return this.path + "/design.json" }
  
  // run json converter
  run(cb) {
    scanner.runbit2json(this.bitstream, this.getJSON(), this.getLog(), cb)
  }
}



// convert bitstream to fasm
class FASMConvertJob extends BitJob {

  constructor(path, bitstream) {
    super(path, bitstream)
    this.job_type = "FASMConvertJob"
  }

  getLog()      { return this.path + "/log.txt" }
  getFASM()     { return this.path + "/design.fasm" }
  
  // run json converter
  run(cb) {
    scanner.runbit2fasm(this.bitstream, this.getFASM(), this.getLog(), cb)
  }
}



// check for shell in bitstream
class CheckShellJob extends BitJob {

  constructor(path, bitstream) {
    super(path, bitstream)
    this.job_type = "CheckShellJob"
  }

  getLog()      { return this.path + "/log.txt" }
  getOutput()   { return this.path + "/output.txt" }
  
  // run shell checker
  run(cb) {
    scanner.runCheckShell(this.bitstream, this.getOutput(), this.getLog(), (err) => {
      if (err) return cb(err)
      scanner.parseCheckShell(this.getOutput(), (err, data) => {
        if (err) return cb(err)
        this.results = data
        cb()
      })
    })
  }

  get results()         { return this.getJson("results")             }
  set results(results)  { this.setJson("results", results)           }
}



// perform a virus scan run on a bitstream
class VirusScanJob extends BitJob {
  constructor(path, bitstream, scan_type="cpp") {
    super(path, bitstream)
    this.job_type = "VirusScanJob"

    // init job data
    if (this._json.fresh) {
      this.scan_type = scan_type
    }
  }

  getReport()    { return this.path + "/vsreport.txt" }
  getLog()       { return this.path + "/vslog.txt" }
  getGlitchPNG() { return this.path + "/glitch.png" }

  // perform scan job and parse output
  run(cb) {
    if (this.scan_type == "cpp") {
      scanner.runVSCPP(this.bitstream, this.getReport(), this.getLog(), this.getGlitchPNG(), (err) => {
        if (err) {
          console.log("error running cpp scan")
          console.log(err)
          return cb(err)
        }

        console.log("parsing cpp scan report " + this.getReport())
        scanner.parseVSCPPOut(this.getReport(), (err, data) => {
          if (err) return cb(err)

          this.results = data
          return cb()
        })
      })
    } else if (this.scan_type == "python") {
      // python scanner can only use zu3eg at the moment
      let config = "virusscanner/resources/config.ini"
      let chip = "xczu3eg"
      console.log("running python scan on " + this.bitstream)
      scanner.runVSPy(this.bitstream, config, chip, this.getReport(), this.getLog(), (err) => {
        if (err) {
            console.log("error running python scan")
            console.log(err)
            return cb(err)
        }
        console.log("parsing python scan report " + this.getReport())
        scanner.parseVSPyOut(this.getReport(), (err, data) => {
          if (err) {
            console.log("error parsing python scan")
            console.log(err)
            return cb(err)
          }
          console.log("parsing python scan complete")
          this.results = data
          return cb()
        })
      })
    } else {
      return cb("No such scan type" + this.scan_type)
    }
  }
  
  // first class json vars
  get scan_type()       { return this.getJson("scan_type")           }
  set scan_type(type)   { this.setJson("scan_type", type)            }
  get results()         { return this.getJson("results")             }
  set results(results)  { this.setJson("results", results)           }
}


module.exports = {BitstreamStore, Bitstream, BitJob, BitPNGJob, JSONConvertJob, FASMConvertJob, VirusScanJob, CheckShellJob}


