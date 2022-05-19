"use strict"
const fs       = require("fs")
const cprocs   = require("child_process")
const path     = require("path")
const readline = require("readline")

//const loc_clut_tools = "../../vs-cpp/VirusScannerCPP/scanner"
//const loc_vs_py   = "../../vs-python/virusscanner"

const loc_clut_tools = "/home/joe/projects/scanner/"
const loc_vs_py  = "/home/joe/projects/vs-python/"

// convert bit to png
function runbit2png(bitstream, output, logfile, cb) {
  let args = [bitstream, output]
  let logstream = fs.createWriteStream(logfile)
  logstream.on("open", () => {
    process.env.LD_LIBRARY_PATH = "./build"
    let proc = cprocs.spawn("./build/bit2png", args, {cwd: loc_clut_tools, stdio: [null, logstream, logstream]})
    proc.on("exit", (err) => {
      if (err)
        return cb(err)
      return cb()
    })
  })
}

// check bitstream matches shell
function runCheckShell(bitstream, output, logfile, cb) {
  let args = [bitstream, output]
  let logstream = fs.createWriteStream(logfile)
  logstream.on("open", () => {
    process.env.LD_LIBRARY_PATH = "./build"
    let proc = cprocs.spawn("./check_shell.sh", args, {cwd: loc_clut_tools, stdio: [null, logstream, logstream]})
    proc.on("exit", (err) => {
      if (err)
        return cb(err)
      return cb()
    })
  })
}

function parseCheckShell(output, cb) {
  fs.readFile(output, "utf8", (err, data) => {
    if (err) return cb(err)
    cb(null, data.includes("pass"))
  })
}

// convert bitstream to fasm
function runbit2fasm(bitstream, output, logfile, cb) {
  let args = [bitstream, output]
  let logstream = fs.createWriteStream(logfile)
  logstream.on("open", () => {
    process.env.LD_LIBRARY_PATH = "./build"
    let proc = cprocs.spawn("./build/bit2fasm", args, {cwd: loc_clut_tools, stdio: [null, logstream, logstream]})
    proc.on("exit", (err) => {
      if (err)
        return cb(err)
      return cb()
    })
  })
}

// convert bitstream to json
function runbit2json(bitstream, output, logfile, cb) {
  let args = [bitstream, output]
  let logstream = fs.createWriteStream(logfile)
  logstream.on("open", () => {
    process.env.LD_LIBRARY_PATH = "./build"
    let proc = cprocs.spawn("./build/bit2json", args, {cwd: loc_clut_tools, stdio: [null, logstream, logstream]})
    proc.on("exit", (err) => {
      if (err)
        return cb(err)
      return cb()
    })
  })
}

// run c++ virus scanner
function runVSCPP(bitstream, output, logfile, glitchmap, cb) {
  let args = [bitstream, output, glitchmap]
  let logstream = fs.createWriteStream(logfile)
  logstream.on("open", () => {
  process.env.LD_LIBRARY_PATH = "./build"
    let proc = cprocs.spawn("./build/virusscanner", args, {cwd: loc_clut_tools, stdio: [null, logstream, logstream]})
    proc.on("exit", (err) => {
      if (err)
        return cb(err)
      return cb()
    })
  })
}

// parse c++ virus scanner report file
function parseVSCPPOut(output, cb) {
  let filestream = fs.createReadStream(output)
  let linestream = readline.createInterface({input: filestream, crlfDelay: Infinity})
  let data = {}
  let type = null
  let scandata = null
  let score = null
  linestream.on("line", (line) => {
    line = line.trim()
    if (line == "")
      return
    
    let typedetect = /^(\w+): ([^\s]+)$/.exec(line)
    if (typedetect) {
      type = typedetect[1]
      scandata = {type: type, score: parseFloat(typedetect[2]), data: []}
      data[type] = scandata
      return
    }
    
    let finaldetect = /^Final score: ([^\s]+)$/.exec(line)
    if (finaldetect !== null) {
      score = parseFloat(finaldetect[1])
      return
    }
    if (scandata)
      scandata.data.push(line)
  })
  linestream.on("close", () => {
    cb(null, {score: score, scans: data})
  })
}

// run python fpga virus scanner
function runVSPy(bitstream, config, chiptype, outfile, logfile, cb) {
  let args = ["-m", "virusscanner", "-i", bitstream, "-c", config, "-n", chiptype, "-o", outfile]
  let logstream = fs.createWriteStream(logfile)
  logstream.on("open", () => {
    let proc = cprocs.spawn("python", args, {cwd: loc_vs_py, stdio: [null, logstream, logstream]})
    proc.on("exit", (err) => {
      if (err)
        return cb(err)
      return cb()
    })
  })
}

// parse python fpga virus scanner report
function parseVSPyOut(output, cb) {
  let filestream = fs.createReadStream(output)
  let linestream = readline.createInterface({input: filestream, crlfDelay: Infinity})
  let data = {}
  let type = null
  let scandata = null
  let score = null
  linestream.on("line", (line) => {
    line = line.trim()
    if (line == "")
      return
    
    console.log("got line: '" + line + "'")
    let typedetect = /^(\w+): ([^\s]+)$/.exec(line)
    if (typedetect) {
      type = typedetect[1]
      console.log("  detected new scan type " + type)
      scandata = {type: type, score: parseFloat(typedetect[2]), data: []}
      data[type] = scandata
      return
    }
    
    let finaldetect = /^Final score: ([^\s]+)$/.exec(line)
    if (finaldetect !== null) {
      score = parseFloat(finaldetect[1])
      console.log("  detected final value " + score)
      return
    }
    if (scandata)
      scandata.data.push(line)
  })
  linestream.on("close", () => {
    console.log("stream closed")
    cb(null, {score: score, scans: data})
  })
}

module.exports = {
  runbit2png, runbit2fasm, runbit2json,
  runCheckShell, parseCheckShell,
  runVSCPP, parseVSCPPOut,
  runVSPy, parseVSPyOut}
