// File Magic Signatures 
include "ft_exe.yara"
include "ft_rar.yara"
include "ft_zip.yara"
include "ft_ole_cf.yara"
include "ft_swf.yara"
include "ft_office_open_xml.yara"
include "ft_rtf.yara"
include "ft_tar.yara"
include "ft_gzip.yara"
include "ft_jar.yara"
include "ft_cab.yara"
include "ft_elf.yara"
include "ft_java_class.yara"
include "ft_macho.yara"


// Misc Signatures 
include "misc_coxml_core_properties.yara"
include "misc_compressed_exe.yara"
include "misc_upx_packed_binary.yara"
include "misc_pe_signature.yara"
include "misc_hexascii_pe_in_html.yara"
include "misc_no_dosmode_header.yara"
