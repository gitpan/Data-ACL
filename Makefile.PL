use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
$x = WriteMakefile(
    'NAME'	=> 'Data::ACL',
    'VERSION_FROM' => 'ACL.pm', # finds $VERSION
    'PREREQ_PM' => {'Set::NestedGroups' => 0},
);

print $x;
