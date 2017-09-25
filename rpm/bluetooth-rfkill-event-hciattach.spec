Name: bluetooth-rfkill-event-hciattach
Summary: Bluetooth rfkill event daemon
URL: https://downloadcenter.intel.com/Detail_Desc.aspx?DwnldID=24389
Version: 1.0
Release: 1
License: GPLv2
Source0: %{name}-%{version}.tar.bz2
Requires: glib2
Requires: bluez5-tools
BuildRequires: bluez5-libs-devel
BuildRequires: glib2-devel
Provides:   bluetooth-rfkill-event

%description
Bluetooth rfkill event daemon. Part of Intel Edison GPL/LGPL sources.
Use bluez5 hciattach for patch download.

%package configs-mer
Summary:    Default configuration for bluetooth-rfkill-event
Requires:   %{name} = %{version}-%{release}
Provides:   bluetooth-rfkill-event-configs

%description configs-mer
This package provides default configuration for bluetooth-rfkill-event

%prep
%setup -q -n %{name}-%{version}/bluetooth-rfkill-event

%build
make

%install
rm -rf %{buildroot}
%make_install

%files
%defattr(-,root,root,-)
# >> files
%{_sbindir}/bluetooth_rfkill_event
/%{_lib}/systemd/system/bluetooth-rfkill-event.service
/%{_lib}/systemd/system/network.target.wants/bluetooth-rfkill-event.service
# << files

%files configs-mer
%defattr(-,root,root,-)
# >> files configs-mer
%dir %{_sysconfdir}/bluetooth-rfkill-event
%{_sysconfdir}/sysconfig/bluetooth-rfkill-event
# << files configs-mer
