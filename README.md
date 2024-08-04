# VX-Underground extractor

A system for extracting files from VX-Underground releases.

Run with:
```sh
vx-underground-extractor /path/to/vx-underground /path/to/extract/to
```

The extractor will find the family directory in the vx-underground archive
and process all the files inside.

The output directory will be created. Inside the output directory,
a directory for each type of processing will be created.

- `extracted`: Files that were extracted from the archive.
- `cart`: A [cart file](https://github.com/CybercentreCanada/cart) for each sample, with metadata about the family and capture date.
- `ghidra_projects`: A Ghidra project for each malware family, containing each sample pre-analyzed.
- `binaryninja_projects`: A BinaryNinja project for each family, containing each sample pre-analyzed.

There are plans to add more analysis:
- [BSim Binary Similarity](https://github.com/NationalSecurityAgency/ghidra/tree/master/GhidraDocs/GhidraClass/BSim) database: A big database of all samples, tagged and categorized. Useful for triaging and finding similar samples, and tracking changes over time.