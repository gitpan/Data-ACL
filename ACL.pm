package Data::ACL::Realm;
use strict;
use Carp;
use vars qw($VERSION);
$VERSION = '0.01';

sub new {
        my ($class, $set) = @_;
        bless {'policies' => [], 'set' => $set}, $class;
}

sub AddPolicy {
        my $self = shift;
	my $right = shift;
        $right =~ tr/a-z/A-Z/;
        croak "Policy should be either Allow or Deny" unless
                ($right eq 'ALLOW' || $right eq 'DENY');
        push(@{$self->{'policies'}}, [$right, @_]);
}

sub Allow {
	my $self = shift;
        $self->AddPolicy('Allow', @_);
}

sub Deny {
	my $self = shift;
        $self->AddPolicy('Deny', @_);
}

sub Is {
	my ($user, $group, $set) = @_;
	return 1 if ($group =~ /^all$/i);
	if ($group =~ s/^\.//) {
		return $group eq $user;
	}
	return undef unless $set->member($user);
	return $set->member($user, $group);
}

sub IsAuthorized {
        my ($self, $user) = @_;
        my $result = 1;
        my @policies = @{$self->{'policies'}};
        my $set = $self->{'set'};
        foreach (@policies) {
                my ($right, $group, $except) = @$_;
                if (Is($user, $group, $set) &&
				!($except && Is($user, $except, $set))) {
                        $result = ($right eq 'ALLOW');
                }
        }
        $result;
}

package Data::ACL;

use strict;
use Set::NestedGroups;
use Carp;

sub new {
        my ($class, $set) = @_;
        bless {'realms' => {}, 'set' => $set}, $class;
}

sub Realm {
        my ($self, $realm) = @_;
        $self->{'realms'}->{$realm} ||= new Data::ACL::Realm($self->{'set'});
        $self->{'realms'}->{$realm};
}

sub AddPolicy {
	my $self = shift;
        my $obj = $self->Realm(shift);
        $obj->AddPolicy(@_);
}

sub IsAuthorized {
        my ($self, $user, $realm) = @_;
        my $obj = $self->{'realms'}->{$realm};
        croak "Realm $realm undefined" unless (UNIVERSAL::isa($obj, 'Data::ACL::Realm'));
        my $default = $self->{'realms'}->{'all'};
        if (UNIVERSAL::isa($default, 'Data::ACL::Realm')) {
                return undef unless ($default->IsAuthorized($user));
        }
        $obj->IsAuthorized($user);
}


1;


# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Data::ACL - Perl extension for simple ACL lists

=head1 SYNOPSIS

  use Data::ACL;
  use Set::NestedGroups; # You should acquire this module from CPAN

  my $groups = new Set::NestedGroups;
  $groups->add('root', 'wheel');
  $groups->add('wheel', 'staff');
  $groups->add('webmaster', 'staff'); # See Set::NestedGroups documentation

  my $acl = new Data::ACL($groups);
  my $web = $acl->Realm("web");
  $web->Deny('all');
  $web=>Allow('staff');
  $web->Deny('.boss'); # User boss, not group

  &DenyAccess unless $acl->IsAuthorized($user, 'web');

=head1 DESCRIPTION

This module implements Deny/Allow series, and requires Set::NestedGroups
to define the groups.

Permissions are given per realm. A special realm called 'all' may contain
prerequisites for all other realms. If evaluating that realm results in
denying access, the specific realm is not evaluated. Otherwise evaluation
proceeds to it.

=head1 AUTHOR

Ariel Brosh, L<schop@cpan.org>

=head1 COPYRIGHT

This module is distributed under the same terms as Perl itself.

=head1 COMMERCIAL SUPPORT

Commercial support may be obtained via Raz Information Systems, Israel,
raz@raz.co.il. No royalty is needed whatsoever for using the module,
including in commercial applications.

=head1 SEE ALSO

perl(1), L<Set::NestedGroups>.

=cut
