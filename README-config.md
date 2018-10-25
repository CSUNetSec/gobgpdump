#Guide on using gobgpdump's configuration option

When parsing data over large amounts of files, the -conf option in 
gobgpdump can be very helpful. Rather than passing each individual
file name to gobgpdump, you pass it the information necessary to search
the filesystem for your MRT files. This can make it easy to do a dump
of tens of thousands of files.

The basic form of the -conf option is this:

gobgpdump -conf <collector format> <config file>

The config file is small file with a single JSON object, in the form:

{"Collist":[""],
"Start":"",
"End":"",
"Lo":"stdout",
"So":"stdout",
"Do":"stdout",
"Wc":1,
"Fmtr":"text",
"Srcas":"",
"Destas":"",
"Anyas":"",
"Prefixes":"",
"Debug":boolean
}

All fields are required, except the filter fields. In this case, only
the last three: Srcas, Destas and PrefList are not required.

The first three (Collist, Start, End) relate to the collector format
file, and will be discussed in that section.

Lo, So, and Do are output redirection options. Lo is the file to place
log output. So redirects statistical output, how fast files are being
processed, how many messages pass filters, etc. Do redirects dump
output. Whatever format chosen will appear in this file. All are set to
stdout in the example above, but if changed, will create/truncate a
file.
gobgpdump does not recognize stderr as a special file.

Wc is worker count. This number of goroutines will be launched to
process files, with each goroutine processing a single file at a time.

Fmtr is the output format chose. Several are available, visible with
gobgpdump -h

Srcas , Dstas, Anyas and Prefixes are comma separated lists to match on each
element of the corresponding fields. Anyas means an AS anywhere in the AS-path
Prefix matching works in a "contained" function. 
So for example a prefix list of "132.9.0.0/16" will match the contained
subnet of 132.9.12.0/24

##collector format file
Collector Format is a special file to help gobgpdump navigate your
filesystem. It has this format:

{base} <path>
{default} <path>
<nickname> <path>
<nickname> <path>
...

Here is an example collector format file:

{base} /home/will/gobgpdumpdata
{default} /{x}/{yyyy.mm}
special /different/{yyyy.mm}

{base} is applied before every other rule.

The first two lines must begin with {base} and {default}, respectively.
This relates to the Collist field. The collist is a string array of
names. These are nicknames for directories. If a entry in Collist has
a nickname, as special does in the example above, that path will be 
used. Otherwise, the default rule is used, and the {x} is replaced
with the nickname used.

gobgpdump looks for MRT files in directories with the format yyyy.mm
Start and end must be times, in this format. Such as 2017.02, to mean
February of 2017

As an example:
{"Collist":["special","notspecial"],
"Start":"2017.02",
"End":"2017.02",
...

gobgpdump would search for <special>'s files in:
/home/will/gobgpdumpdata/different/2017.02

And it would search for <notspecial>'s files in:
/home/will/gobgpdumpdata/notspecial/2017.02
