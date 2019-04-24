#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import os.path
import shutil

filepath = "./data/"
manifest_template = "./manifest.template"
manifest = "./manifest"


if os.path.exists(manifest_template):
    shutil.copyfile(manifest_template, manifest)
else:
    print "ERROR: Not exist manifest.template! Check your files..."

    
f = open(manifest, 'a')

for name in os.listdir(filepath):
    if os.path.isfile(filepath + name) and name[-11:] == ".data.cpabe":
        if "." in name[:-11]:
            print "WARNING: do not use '.' in filename without extension. Therefore, " + name + " could not write on manifest."
        else:
            noExtension = name[:-11].replace("-", "_")
            string = "sgx.trusted_files." + noExtension + " = file:data/" + name + "\n"
            f.write(string)
            print "write " + name + " on manifest..."
    else:
        print "WARNING: file extension must be used '.data.cpabe'. Therefore, " + name + " could not write on manifest."

f.close()
