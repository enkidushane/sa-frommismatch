package Mail::SpamAssassin::Plugin::FromMismatch;
my $VERSION = 0.1;

use strict;
use warnings;
use bytes;
use re 'taint';
use Errno qw(EBADF);

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Constants qw(:sa :ip);
#use Mail::SpamAssassin::Logger qw(would_log);

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

sub dbg {
    my $msg = shift;
    return Mail::SpamAssassin::Logger::dbg("FromMismatch: $msg");
}

sub new {
    my $class = shift;
    my $mailsaobject = shift;

    # some boilerplate...
    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsaobject);
    bless ($self, $class);

    # the important bit!
    $self->register_eval_rule("check_for_from_mismatch");

    return $self;
}

sub check_for_from_mismatch {
    my ($self, $pms) = @_;

    my $from_name = lc($pms->get('From:name'));
    
    # If $from_name is empty, then quit now
    return 0 if ( $from_name eq "" );

#    if ( would_log("dbg", "check") == 2 ) {
#	dbg("check: running FromMismatch plugin");
#    }

    # If there's no "@" in the name part, then quit now
    if (index($from_name, "@") == -1 ) {
	dbg("info: From:name doesn't appear to contain an email address.  Bailing out");
	return 0;
    }

    my $from_addr = lc($pms->get('From:addr'));
    # We can reasonably count on From:addr to have a single, real domain
    my (undef, $addr_fqdn) = split("@", $from_addr);
    dbg("info: FQDN in From:addr is \"$addr_fqdn\"");

    # But name_domain isn't so clean
    # Possible challenges include:
    #   Use of "@" in the textual name is not uncommon.  For instance:
    #     "Data Courses @ GA"
    #     Or this business (https://atproperties.com)
    #   More than one "@"    
    #
    # We should also check for some legitimate uses, like:
    # RT puts the "true" sender in the name part
    # Mailing lists that do something similar (yahoogroups?)
    my $exception = "";
    $exception = "behalf of" if ( $from_name =~ m/behalf of .*\@/ );
    $exception = "via" if ( $from_name =~ m/\@.* via/ );

    unless ( $exception eq "" ) {
	dbg("info: Maybe legitimate use, based on \"$exception\"");
	return 0;
    }

    my $mismatch = 0; # Assume there's no mismatch

    dbg("info: From:name is \"$from_name\"; Splitting into parts");

    my @name_parts = split("@", $from_name);
    
    # We can assume the first item is not a domain
    shift @name_parts;


    # Now handle any remaining parts
    foreach my $part (@name_parts) {
	dbg("info: Name part is \"$part\"");

	# If a part doesn't match these, then just move on to the next part
	if ( $part !~ m/^[a-z]/ ) {
	    dbg("info: $part doesn't look valid: First character isn't a letter; Skipping check");
	    next;
	}

	if ( $part !~ m/\./ ) {
	    dbg("info: $part doesn't look valid: No literal dots; Skipping check");
	    next;
	}

	# Remove any trailing text
	$part =~ s/^([a-z0-9\._-]*)[^a-z0-9\._-].*$/$1/;
	chomp $part;
	dbg("info: Cleaned name part is \"$part\"");
	

	if ( $part =~ /[^a-z0-9\._-]/ ) {
	    dbg("info: $part doesn't look valid: Invalid characters; Skipping check");
	    next;
	}

	if ( $part !~ /^([a-z][a-z0-9-]+[a-z0-9]\.){1,}[a-z][a-z0-9-]*[a-z0-9]$/ ) {
	    dbg("info: $part doesn't look valid: Invalid format; Skipping check");
	    next;
	}
	
        # If we're still here this is probably a valid domain
	# Though we could do more checks (using Regist(ry|rar)Boundaries)
	dbg("info: $part looks like a FQDN; comparing $addr_fqdn to $part");
	if  ($addr_fqdn ne $part ) {
	    $mismatch = 1;
	    dbg("info: Looks like a mismatch");
	} else {
	    dbg("info: Looks like a match, so we're good");
	    return 0;
	}

	# If we're still here, there's been a mismatch
	# But let's check 2nd level domains in case one is just a subdomain of the other
	my $addr_domain = $addr_fqdn;
	$addr_domain =~ s/^.+\.([^\.]+\.[^\.]+)$/$1/;
	if ( $addr_domain eq '' ) {
	    dbg("info: Address domain ended up empty.  Bailing out");
	    $mismatch = 0;
	    next;
	}

	my $name_domain = $part;
	$name_domain =~ s/^.+\.([^\.]+\.[^\.]+)$/$1/;
	if ( $name_domain eq '' ) {
	    dbg("info: Name domain ended up empty.  Bailing out");
	    $mismatch = 0;
	    next;
	}

	if ( $addr_domain eq $name_domain ) {
	    dbg("info: 2nd-level domains match though, so we're good");
	    $mismatch = 0;
	}	
    }

    
    return 1 if $mismatch == 1;

    return 0;

}
