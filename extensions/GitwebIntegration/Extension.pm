# -*- Mode: perl; indent-tabs-mode: nil -*-
#
# The contents of this file are subject to the Mozilla Public
# License Version 1.1 (the "License"); you may not use this file
# except in compliance with the License. You may obtain a copy of
# the License at http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS
# IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
# implied. See the License for the specific language governing
# rights and limitations under the License.
#
# The Original Code is the GitwebIntegration Bugzilla Extension.
#
# The Initial Developer of the Original Code is YOUR NAME
# Portions created by the Initial Developer are Copyright (C) 2011 the
# Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   YOUR NAME <YOUR EMAIL ADDRESS>

package Bugzilla::Extension::GitwebIntegration;
use strict;
use base qw(Bugzilla::Extension);

our $VERSION = '0.2';

# See the documentation of Bugzilla::Hook ("perldoc Bugzilla::Hook" 
# in the bugzilla directory) for a list of all available hooks.

sub bug_format_comment {
	my ($self, $args) = @_;

	my $regexes = $args->{'regexes'};

	# Each regex is run in order, and later regexes don't modify
	# earlier matches, due to some cleverness in Bugzilla's internals.
	my $commit_match = qr/gitweb:\/\/([a-zA-Z0-9\/\-]+\.git)\/([0-9a-f]{5,40})/;
	push(@$regexes, { match => $commit_match, replace => \&_replace_commit });
	my $review_match = qr/gitweb:\/\/([a-zA-Z0-9\/\-]+\.git)\/([0-9a-f]{5,40})/;
	push(@$regexes, { match => $review_match, replace => \&_replace_review });
}

sub _replace_commit {
	my $args = shift;
	my @value = $args->{matches};
	# $match is the first parentheses match in the $bar_match regex 
	# in bug-format_comment.pl. We get up to 10 regex matches as 
	# arguments to this function.
	my $repo = $args->{matches}->[0];
	my $ref = $args->{matches}->[1];
	return qq{<a href="http://git.sabayon.org/$repo/commit/?id=$ref">$ref</a>};
};

__PACKAGE__->NAME;
