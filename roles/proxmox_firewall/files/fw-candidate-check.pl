#!/usr/bin/perl
# Offline validation of candidate Proxmox firewall files. Never reads the
# live firewall files or touches the running ruleset.
#
# Usage: fw-candidate-check.pl <dir>
#   <dir>/cluster.fw     candidate datacenter file (enable forced to 1)
#   <dir>/host.fw        candidate host file of the node running the check
#   <dir>/host-<n>.fw    candidate host files of the other nodes (parse only)
#   <dir>/<vmid>.fw      candidate guest files (parse only)
# Exit 0 only when no rule has a parse error, the offline compile emits no
# warning, the VXLAN guard rule is present and PVEFW-HOST-IN exists.
use strict;
use warnings;
use PVE::Cluster;
use PVE::Firewall;

my ($dir) = @ARGV;
die "usage: $0 <dir>\n" if !$dir || !-f "$dir/cluster.fw" || !-f "$dir/host.fw";

my @problems;
my @warnings;
local $SIG{__WARN__} = sub { push @warnings, $_[0] };

sub collect {
    my ($where, $rules) = @_;
    for my $rule (@{ $rules // [] }) {
        next if !$rule->{errors};
        for my $field (sort keys %{ $rule->{errors} }) {
            push @problems, "$where: $field: $rule->{errors}->{$field}";
        }
    }
}

PVE::Cluster::cfs_update();
my $cluster = PVE::Firewall::load_clusterfw_conf("$dir/cluster.fw");
collect('cluster.fw [RULES]', $cluster->{rules});
for my $group (sort keys %{ $cluster->{groups} // {} }) {
    collect("cluster.fw [group $group]", $cluster->{groups}->{$group});
}

opendir(my $dh, $dir) or die "cannot read $dir: $!\n";
my @files = sort readdir($dh);
closedir($dh);
for my $file ('host.fw', grep { /^host-.+\.fw$/ } @files) {
    my $host = PVE::Firewall::load_hostfw_conf($cluster, "$dir/$file");
    collect($file, $host->{rules});
}
for my $file (grep { /^\d+\.fw$/ } @files) {
    my ($vmid) = $file =~ /^(\d+)\.fw$/;
    my $guest = PVE::Firewall::load_vmfw_conf($cluster, 'vm', $vmid, $dir);
    collect($file, $guest->{rules});
}

my ($ruleset) = PVE::Firewall::compile(undef, undef, { testdir => $dir, qemu => {}, lxc => {} });
my $filter = $ruleset->{filter} // {};
my ($rules, $vxlan) = (0, 0);
for my $chain (keys %$filter) {
    my @chain_rules = @{ $filter->{$chain} // [] };
    $rules += @chain_rules;
    $vxlan += grep { /--dport 4789\b/ } @chain_rules;
}
push @problems, "compile warning: $_" for @warnings;
push @problems, 'VXLAN guard rule missing from compiled ruleset' if !$vxlan;
push @problems, 'PVEFW-HOST-IN missing from compiled ruleset' if !exists $filter->{'PVEFW-HOST-IN'};

printf "filter_chains=%d rules=%d vxlan_guard=%d problems=%d\n",
    scalar(keys %$filter), $rules, $vxlan, scalar(@problems);
print "PROBLEM: $_\n" for @problems;
exit(@problems ? 1 : 0);
