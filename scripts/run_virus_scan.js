const vs = require("./virusscanner")


console.log("Running scan")
bitstream = "virusscanner/resources/input_designs/ring_osci_MUX.bit"
config = "virusscanner/resources/config.ini"
chip = "xczu3eg"
output = "../output7.txt"

vs.runVSPy(bitstream, config, chip, output, err => {
  if (err)
    console.log(err)
  else {
    vs.parseVSPyOut("./virusscanner/" + output, data => {
      console.dir(data)
    })
  }
})

/* vs.parseVirusScannerOutput("./virusscanner/"+output, data => {
  console.dir(data)
}) */
