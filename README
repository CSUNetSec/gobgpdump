1) Input
	1.1) BGP updates
		gobgpdump can parse BGP updates and a large subset of BGP attributes. 
		gobgpdump does not read from stdin as other analyzing tools do, all
		messages are read from a file or series of files. The input file should
		be a series of MRT messages in binary format.

		No special option must be used to read BGP update messages, message type
		is determined by MRT type and subtype.
		Example:
		gobgpdump <input file>
	1.2) RIB Dumps
		gobgpdump can also parse files containing RIB dumps. At the moment, only
		TABLE_DUMP_V2 is supported, and only AFI/SAFI subtypes are supported on
		it.

		Like bgp update messages, message type is determined from MRT type and
		subtype. However, in the case of a ribdump, if rib messages are mixed with
		bgp update messages in the same file, neither will be read correctly.
		Example:
		gobgpdump <input file>
	1.3) Multiple files
		1.3.1) Command line
			gobpgdump can accept multiple input files as arguments. Any command
			line arguments not determined to be a part of the command flags will
			be considered an input file.
			Input files will be processed in the order they are provided on the
			command line.
			Example:
			gobgpdump <input file 1> <input file 2> etc.
		1.3.2) The -conf option
			The -conf option was created to process large quantities of data files
			without having to specify all of them on the command line.  
			The -conf option takes two arguments, which are used as templates to search
			the file system for designated files. No particular order is guaranteed with
			this system.

			For more information on the -conf option, see README-config.md
	1.4) Bz2
		If an input file is seen to have an extension of .bz2, it will be run through
		the bz2 decompression algorithm. Only the file extension is checked, never the
		file data.
		No special flag is used, gobgpdump will decide based off of file extensions.
		Note, when using the ID formatter, the output data will be the uncompressed
		version of the data.
2) Output
	2.1) Text
		The default option for a gobgdump output format is text. Depending on
		the input file recieved, it could look like:
		>MRT Header: ---
		>BGP4H Header: ---
		>BGP Header: ---
		>BGP Update: ---

		Or, if it were a rib file,
		MRT Header: ---
		RIB Header: ---
		RIB Entry: ---

		These will be repeatedly output for each entry in the input file to stdout
		unless redirected.
		Example:
		gobgpdump -fmtr text <input file>
		gobgpdump <input file>
	2.2) JSON
		JSON output is available for all supported protocols. The output is a series
		of messages (not an array) in valid JSON to stdout.

		Example:
		gobgpdump -fmtr json <input file>
	2.3) Protobuf
		gobgpdump does not currently have a user available option for dumping messages
		in protobuf format. However, the underlying library used to parse messages,
		protoparse, does parse directly into a protobuf.

		For more information, see github.com/CSUNetSec/protoparse
	2.4) ID
		This is the identity formatter. This will read in a binary file, and output the
		exact input data. This is mainly used for creating subsets of a file after
		applying some amount of filters to it.
		Example:
		gobgpdump -fmtr id <input file>
	2.5) pup
		This formatter stands for print unique prefixes. With this option, gobgpdump
		produces no message output until it is finished parsing every message of every
		input file. After it is finished running, it prints a newline-separated list of
		every prefix seen at least once in one of the input files. If a prefix appears,
		and a parent prefix appears later in the input files, the child prefix is ignored.
		Example:
		gobgpdump -fmtr pup <input file>
	2.6) pts
		This formatter stands for prefix time series. Like pup, this formatter records
		all unique prefixes, however this also records the timestamp and message number
		of every appearance of the highest level prefix. The output format is a gob, so
		redirecting outside of stdout is recommended.
		Example:
		gobgpdump -fmtr pts <input file>
	2.7) Redirecting output
		gobgpdump produces three distinct varieties of output messages. The first is
		message output, which consists of only bgp or rib messages contained in input
		files. The second is statistical output, which contains details of messages filed,
		filters passed and the time taken to do so, and the last is log output. Log output
		is used to indicate any errors in parsing a message.
		Each output is directed to stdout by defualt.
		Each type of output may be redirected using a specific gobgpdump option, -o, -so,
		and -lo
		To redirect message output:
		gobgpdump -o <output file> <input file>
		
		To redirect statistical output:
		gobgpdump -so <stat file> <input file>

		To redirect log output:
		gobgpdump -lo <log file> <input file>

		When working with a large quantity of input files, redirecting log output is
		recommended, as it can quickly clutter stdout.
	2.8) ML text output
		A textual formatter that prints one line per event, suitable for Machine Learning
		purposes.
3) Filter options
	3.1) Prefix filtering
		Possibly the most useful type of filtering, gobgpdump has the option of only
		outputting messages if a particular prefix appears in said message. If multiple
		prefixes are given, a message will pass on to output if any of the prefixes listed
		appear in the message. This is used on both BGP Update and RIB messages.
		Example:
		gobgpdump -prefixes 0.0.0.0/24 <input file>
		gobgpdump -prefixes 1.2.3.4/24,5.6.7.8/16 <input file>

		If a prefix string is improperly formatted, no message will pass, resulting in no output.
	3.2) src AS filtering
		Another option is to filter by src AS. This filter looks at the AS Path of every message
		in the input file, and if the last (source) AS in the AS path matches one of those given,
		the message will pass on to output.
		Example:
		gobgpdump -srcas 1234 <input file>
		gobgpdump -srcas 56,78 <input file>
	3.3) dest AS filtering
		The last filter option is by destination AS. This is the 0th AS in the AS path of every
		message.
		Example:
		gobgpdump -destas 1234 <input file>
		gobgpdump -destas 56,78 <input file>
4) Multicore options
	gobgpdump can operate with mulitple cores to dramatically increase the speed of a dump
	operation. Multiple cores can only be leveraged on multiple files, only 1 thread is ever
	operating on a single file.
	gobgpdump's concurrency option is accessed through the -wc option. This stands for worker
	count, and is the maximum number of threads to be launched by gobgpdump, with a cap of 16.
	Example:
	gobgpdump -wc 2 <input file 1> <input file 2>
5) Complex examples
	This repository includes small example MRT files, uncompressed, in the /examples folder.
	These can  be used to show the complex functionality of gobgpdump.

	If I wanted to read in an MRT file, find messages originating from autonomous system 6629 or 
	4847, and print all the prefixes advertized or withdrawn from that system and store it in a 
	file called temp, I could run this:
	gobgpdump -src 4847,6629 -fmtr pup -o temp /examples/collector1/2017.01/arch0

	If I wanted to output every message that contained the prefix 153.2.224.0/24 as json, I could
	run:
	gobgpdump -prefixes 196.216.241.0/24 -fmtr json /examples/collector1/2017.02/arch1

	If I wanted to save every message originating from AS 4847 from multiple files as an MRT file
	for later analyzation in a file called 4847-messages, and I wanted to read the files with a max 
	of 4  cores, I could run:
	gobgpdump -srcas 4847 -fmtr id -o 4847-messages -wc 4 examples/all/*

	If I was dealing with too many files in different directories to use wildcards effectively,
	I would use the configuration option.
	gobgpdump -conf example/example-formats example/conf-file
	For more information on how to build and modify those files, read README-config.md
