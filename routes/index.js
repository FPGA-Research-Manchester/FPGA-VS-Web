"use strict"
const betterq = require("better-queue")
const crypto  = require("crypto")
const express = require("express")
const fs      = require("fs")
const multer  = require("multer")

const repoman = require("../helpers/repoman")      // file backed repository of bitstreams and jobs

// setup multer uploads
const storage = multer.memoryStorage()
const bsupload = multer({storage})

// load bitstream repository
const repo = new repoman.BitstreamStore(process.cwd() + "/store")

// queue just calls the host function for each job 
const vsqueue = new betterq(function (input, cb) {
  input.host(cb)
}, { concurrent: 32 })

// called to add a new bitstream to the repo
function newBitstream(filename, filebuffer, jobname, scanlanguage, ispublic, callback) {

  // setup bitstream
  let bitstream_id = "" + Math.floor(new Date().getTime() / 1000)
  let bitstream_key = crypto.randomBytes(32).toString('hex')
  let bitstream = repo.newBit(bitstream_id, jobname, filename, bitstream_key, ispublic)
  fs.writeFile(bitstream.fullPath(), filebuffer, (err) => {
    if (err) return callback(err)

    // setup jobs
    let job_png   = new repoman.BitPNGJob(bitstream.path + "/job_png", bitstream.fullPath())
    let job_check = new repoman.CheckShellJob(bitstream.path + "/job_check", bitstream.fullPath())
    let job_json  = new repoman.JSONConvertJob(bitstream.path + "/job_json", bitstream.fullPath())
    let job_fasm  = new repoman.FASMConvertJob(bitstream.path + "/job_fasm", bitstream.fullPath())
    let job_vscan = new repoman.VirusScanJob(bitstream.path + "/job_vscan", bitstream.fullPath(), scanlanguage)

    // load jobs into parent
    bitstream.addJob("job_png", job_png)
    bitstream.addJob("job_check", job_check)
    bitstream.addJob("job_json", job_json)
    bitstream.addJob("job_fasm", job_fasm)
    bitstream.addJob("job_vscan", job_vscan)

    // push all jobs into queue
    vsqueue.push(job_png)
    vsqueue.push(job_check)
    vsqueue.push(job_json)
    vsqueue.push(job_fasm)
    vsqueue.push(job_vscan)

    return callback(null, bitstream)
  })
}



// top level routing
const router = express.Router()

// setup static public routes
router.use(express.static("public"))

// setup home page
router.get("/", (req, res) => {
  console.log("Viewing home page")
  res.render("pages/index")
})

// bitstream upload page
router.get("/scan", (req, res) => {
  console.log("Viewing scan list")
  res.render("pages/scan_list", {repo})
})

// bitstream upload page
router.get("/scan/new", (req, res) => {
  console.log("Viewing bitstream upload page")
  res.render("pages/scan_new")
})

router.post("/scan/new", bsupload.single("bitstream"), (req, res) => {
  let jobname = req.body.jobname
  if (jobname == "") jobname = req.file.originalname
  console.log("New bistream is being uploaded")
  newBitstream(req.file.originalname, req.file.buffer, jobname, req.body.lang, req.body.public == "true", (err, bitstream) => {
    if (err) console.log(err)
    console.log("New bistream upload complete, redirecting")
    res.redirect("/vs/scan/" + bitstream.key)
  })
})

// view scan page
router.get("/scan/:id", (req, res) => {
  let bitstream = repo.getBitByKey(req.params.id)
  if (!bitstream) return res.end("Not Found")
  let job = bitstream.getJob("job_vscan");
  console.log(`Viewing bitstream ${bitstream.name}`)
  res.render("pages/scan_view", {bitstream, job, id: req.params.id})
})

// get json data of bitstream
router.get("/scan/:id/json", (req, res) => {
  let bitstream = repo.getBitByKey(req.params.id)
  if (!bitstream) return res.end("Not Found")
  console.log(`Viewing JSON data of bitstream ${bitstream.name}`)
  res.json(bitstream)
})

// get utilisastion image of bitstream
router.get("/scan/:id/img/util", (req, res) => {
  let bitstream = repo.getBitByKey(req.params.id)
  if (!bitstream) return res.end("Not Found")
  let image = bitstream.getJob("job_png").getPNG()
  console.log(`Downloading ${bitstream.name} util png file`)
  res.sendFile(image)
})

// get glitchamp image of bitstream
router.get("/scan/:id/img/glitch", (req, res) => {
  let bitstream = repo.getBitByKey(req.params.id)
  if (!bitstream) return res.end("Not Found")
  let image = bitstream.getJob("job_vscan").getGlitchPNG()
  console.log(`Downloading ${bitstream.name} glitch png file`)
  res.sendFile(image)
})

// get original bitstream file
router.get("/scan/:id/res/bit", (req, res) => {
  let bitstream = repo.getBitByKey(req.params.id)
  if (!bitstream) return res.end("Not Found")
  console.log(`Downloading ${bitstream.name} bitstream`)
  res.download(bitstream.fullPath(), bitstream.name)
})

// get fasm decode of bitstream
router.get("/scan/:id/res/fasm", (req, res) => {
  let bitstream = repo.getBitByKey(req.params.id)
  if (!bitstream) return res.end("Not Found")
  if (!bitstream.getJob("job_check").results)
    return res.end("Not permitted")
  let fasm = bitstream.getJob("job_fasm").getFASM()
  console.log(`Downloading ${bitstream.name} fasm file`)
  res.download(fasm, bitstream.name + ".fasm")
})

// get json graph of bitstream
router.get("/scan/:id/res/json", (req, res) => {
  let bitstream = repo.getBitByKey(req.params.id)
  if (!bitstream) return res.end("Not Found")
  if (!bitstream.getJob("job_check").results)
    return res.end("Not permitted")
  let json = bitstream.getJob("job_json").getJSON()
  console.log(`Downloading ${bitstream.name} json file`)
  res.header('Content-disposition', 'attachment; filename=' + bitstream.name + ".json");
  res.header('Content-type', "application/json");
  res.sendFile(json)
})

// tech page
router.get("/tech", (req, res) => {
  res.render("pages/tech")
})

// team page
router.get("/team", (req, res) => {
  res.render("pages/team")
})


// about page
router.get("/about", (req, res) => {
  res.render("pages/about")
})


module.exports = router

