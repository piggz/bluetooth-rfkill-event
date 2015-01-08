Name: bluetooth-rfkill-event
Summary: Bluetooth rfkill event daemon
URL: https://downloadcenter.intel.com/Detail_Desc.aspx?DwnldID=24389
Version: 1.0
Release: 1
License: GPLv2
Source0: %{name}-%{version}.tar.bz2
Requires: bluez-libs
BuildRequires: bluez-libs-devel
BuildRequires: glib2-devel

%description
Bluetooth rfkill event daemon. Part of Intel Edison GPL/LGPL sources.

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
%config %{_sysconfdir}/firmware/*.conf
# << files
