"use strict"
const ds = require("./repoman.js")

// load repo
let repo     = new ds.BitstreamStore("./store")

// create new bit (uniq_id, friendly_name, bitstream_name, )
let bit      = repo.newBit("new_bit_1", "New Bit 1", "new_bit_1.bit")

// add various bitstream jobs
let stat_job = bit.addJob(new BitStatJob())
let png_job  = bit.addJob(new BitPNGJob())
let vs_job   = bit.addJob(new VirusScanJob())
