INTRODUCTION

This is the README For BankOfEuler version 0.9.1.

BankOfEuler is a public domain zero-knowledge banking server.

The BankOfEuler server (bankserve) only sees encrypted values and is
not aware of the actual quantities stored or transferred.  Homomorphic
properties of the encryption allow the server to combine encrypted
values, producing encrypted sums and differences.  When values are
subtracted, interactive proofs are used to convince the server
that the difference is non-negative.

BankOfEuler enables micropayments by ensuring equal scrutiny for every
transaction.

BankOfEuler enables secure games of chance via shared proof construction.
An example coin-flipping application is included.

BankOfEuler is not finished yet.  It contains security holes.  Read the source
code to know more of the whole truth.

BankOfEuler is named in honor of Leonhard Paul Euler (1707-1783), who
discovered the fact that x^phi(n) = 1 mod n.  For more information, see:
http://en.wikipedia.org/wiki/Leonhard_Euler


SYSTEM REQUIREMENTS

BankOfEuler requires:
	gmp-4.2.1	http://ftp.sunet.se/pub/gnu/gmp/gmp-4.2.1.tar.gz
	stunnel-4.20	http://www.stunnel.org/download/stunnel/src/stunnel-4.20.tar.gz
	openssl-0.9.8e	http://www.openssl.org/source/openssl-0.9.8e.tar.gz


COMPILATION

Before compiling, make sure libgmp.so has been installed in the system library path,
or else add the directory containing this file to the LD_LIBRARY_PATH environment
variable.

To build BankOfEuler, type:
	make

bankshell and bankserve will be produced.


INSTALLATION

To install BankOfEuler, type:
	make install

BankOfEuler will be installed in /usr/local/BankOfEuler.  Symbolic links
to bankshell and bankserve will be created in /usr/local/bin.


RUNNING THE SERVER

stunnel must be in your PATH to run bankserve.

To start the BankOfEuler server, type:
	bankserve > bankserve.log &


TESTING THE CLIENT AND SERVER

stunnel must be in your PATH to run bankshell.

"$BANKOFEULER_HOME" in the following section refers to the installation
directory /usr/local/BankOfEuler.  You can copy /usr/local/BankOfEuler to
a new location and set the BANKOFEULER_HOME environment variable to this
directory in order to run multiple bankshell or bankserve instances with
different configurations.  This directory can also be specified on the
command lines of bankshell and bankserve with the "-d" option.

In order to run the following test cases verbatim with the default
installation, you should first type:
	export BANKOFEULER_HOME=/usr/local/BankOfEuler

A $10 value is provided with the default server installation, in
account 0x75.  $BANKOFEULER_HOME/values should contain one directory
which contains one empty file.  In the default server configuration,
$1 = 2^768, and the name of the empty file will be a hash of an
encryption of 10*2^768.  The name of the directory containing the
file is related to the account number 0x75 in the same way.

bankshell manages values in directories named by your Unix username,
located in $BANKOFEULER_HOME/accounts.  The directory structure
and file-naming are the same as the server-side values directory,
with two differences.  Each directory has a ".id" file containing
the decrypted account number, and the files are no longer empty,
but contain decrypted monetary values.

Initially the accounts directory is empty.

To make bankshell aware of the $10 in account 0x75, type:
	bankshell sync -a 0x75 '$10'

Confirm that it is in your account:
	bankshell list -a 0x75

Check that it is still valued by the server:
	bankshell check -a 0x75 '$10'

It should say "0xa000[...] has value".

To split the $10 value into $2 and $8, type:
	bankshell split -a 0x75 '$10' '$2'

$BANKOFEULER_HOME/values/H297c*/ should now contain exactly two empty files.

You should be able see both values in hexadecimal with bankshell list:
	bankshell list -a 0x75

Check that $2 and $8 have value now:
	bankshell check -a 0x75 '$2'
	bankshell check -a 0x75 '$8'

Check that $10 does not:
	bankshell check -a 0x75 '$10'

To merge these values into $10 again:
	bankshell merge -a 0x75 '$2' '$8'

Check that $10 is valuable again:
	bankshell check -a 0x75 '$10'


Now from the $10, let's put $1 in account 1, 42 in account 2, and $3 in each of
accounts 3 and 4, while leaving $1 in account 0x75:
	bankshell split -a 0x75 '$10' -a 1 '$1' -a 2 '$2' -a 3 '$3' -a 4 '$3' -a 0x75
	bankshell list -a 0x75
	bankshell list -a 1
	bankshell list -a 2
	bankshell list -a 3
	bankshell list -a 4

(A real account number should be random and much larger.  As you can see, knowing
an account number allows you to transfer funds from or to it.)

Randomize the low-order bits of our $1 to obscure its value.  This
will split it into a large part and a small part, discarding the
small part.  Neither the server nor an eavesdropper should be able
to tell which part is which.

	bankshell randomize -a 0x75 '$1'

Check that the randomized $10 is valuable:
	bankshell list -a 0x75 |xargs bankshell check -x 0x75

Now bankshell list -a 0x75 should show only one value, starting with "0xfffffffff"
and very close to $10.


DISTRIBUTION

To prepare a source distribution, edit the version in the Makefile and at the
top of this README, and build your distribution by typing:
	make srcdist

BankOfEuler-$(VERSION).src.tar.gz will be built in this directory.


AUTHOR

BankOfEuler was conceived and written by Dan Brumleve <jdb1729@gmail.com>.

