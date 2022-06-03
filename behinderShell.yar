*
   YARA Rule Set
   Author: mastadon
   Date: 2022-06-03
   Identifier: yara
   Reference: https://github.com/Freakboy/Behinder
*/

/* Rule Set ----------------------------------------------------------------- */

rule _home_kali_yara_shell {
   meta:
      description = "yara - file shell.jsp"
      author = "mastadon"
      reference = "https://github.com/Freakboy/Behinder"
      date = "2022-06-03"
      hash1 = "6b546e78cc7821b63192bb8e087c133e8702a377d17baaeb64b13f0dd61e2347"
   strings:
      $x1 = "AAAAA<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class U extends ClassLoader{U(ClassLoader c){super(c)" ascii
      $s2 = "getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance" ascii
      $s3 = "eb5d925b\";session.putValue(\"u\",k);Cipher c=Cipher.getInstance(\"AES\");c.init(2,new SecretKeySpec(k.getBytes(),\"AES\"));new " ascii
      $s4 = "AAAAA<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class U extends ClassLoader{U(ClassLoader c){super(c)" ascii
      $s5 = "public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals(\"POST\")){String k=\"e45e3" ascii
      $s6 = "().equals(pageContext);}%>bbbb" fullword ascii
      $s7 = "e45e329feb5d925b" ascii
   condition:
      uint16(0) == 0x4141 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule shell_jspx {
   meta:
      description = "yara - file shell.jspx.jsp"
      author = "mastadon"
      reference = "https://github.com/Freakboy/Behinder"
      date = "2022-06-03"
      hash1 = "f4575af8f42a1830519895a294c98009ffbb44b20baa170a6b5e4a71fd9ba663"
   strings:
      $x1 = "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" version=\"1.2\"><jsp:directive.page import=\"java.util.*,javax.crypto.*,jav" ascii
      $s2 = "tInstance(\"AES\");c.init(2,new SecretKeySpec((session.getValue(\"u\")+\"\").getBytes(),\"AES\"));new U(this.getClass().getClass" ascii
      $s3 = "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" version=\"1.2\"><jsp:directive.page import=\"java.util.*,javax.crypto.*,jav" ascii
      $s4 = "ypto.spec.*\"/><jsp:declaration> class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.de" ascii
      $s5 = ").g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);</js" ascii
      $s6 = "p:scriptlet></jsp:root>" fullword ascii
      $s7 = "ineClass(b,0,b.length);}}</jsp:declaration><jsp:scriptlet>String k=\"e45e329feb5d925b\";session.putValue(\"u\",k);Cipher c=Ciphe" ascii
      $s8 = "e45e329feb5d925b" ascii
   condition:
      uint16(0) == 0x6a3c and filesize < 1KB and
      1 of ($x*) and all of them
}

/* Super Rules ------------------------------------------------------------- */