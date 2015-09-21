#!/bin/bash

cat $1 | gzip -dc > $2 2> $3
