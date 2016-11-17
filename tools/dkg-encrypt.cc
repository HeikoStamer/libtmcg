/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2016  Heiko Stamer <HeikoStamer@gmx.net>

   LibTMCG is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   LibTMCG is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with LibTMCG; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*******************************************************************************/

#include <libTMCG.hh>

#include <sstream>
#include <vector>
#include <algorithm>
#include <cassert>

void start_instance
	(std::istream& crs_in, size_t whoami)
{
			
			// create VTMF instance
			BarnettSmartVTMF_dlog *vtmf = new BarnettSmartVTMF_dlog(crs_in);
			if (!vtmf->CheckGroup())
			{
				std::cout << "P_" << whoami << ": " <<
					"Group G was not correctly generated!" << std::endl;
				exit(-1);
			}

			
			// create an Elgamal-based OpenPGP key
			char buffer[2048];
			std::string out, crcout, armor, u, m;
			OCTETS all, pub, sec, uid, uidsig, keyid, sub, ssb, subsig, subkeyid, dsaflags, elgflags;
			OCTETS pub_hashing, sub_hashing, msg, lit, seskey, enc, sed, enc2, seipd, mdc, pkesk;
			OCTETS uidsig_hashing, subsig_hashing, uidsig_left, subsig_left, prefix, mdc_hashing, hash;
			gcry_mpi_t p, q, g, y, x, r, s, h, gk, myk;
			gcry_sexp_t key, dsaparams, signature, sigdata, elgkey;
			gcry_error_t ret;
			size_t erroff;
			std::string d = "(genkey (dsa (nbits 4:2048) (qbits 3:256) (flags transient-key)))";
			ret = gcry_sexp_new(&dsaparams, d.c_str(), d.length(), 1);
			assert(!ret);
			ret = gcry_pk_genkey(&key, dsaparams);
			assert(!ret);
			gcry_sexp_release(dsaparams);
			p = gcry_mpi_new(2048);
			q = gcry_mpi_new(2048);
			g = gcry_mpi_new(2048);
			y = gcry_mpi_new(2048);
			x = gcry_mpi_new(2048);
			r = gcry_mpi_new(2048);
			s = gcry_mpi_new(2048);
			h = gcry_mpi_new(2048);
			gk = gcry_mpi_new(2048);
			myk = gcry_mpi_new(2048);
			ret = gcry_sexp_extract_param(key, NULL, "pqgyx", &p, &q, &g, &y, &x, NULL);
			assert(!ret);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketPubEncode(p, q, g, y, pub);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSecEncode(p, q, g, y, x, sec);
			for (size_t i = 6; i < pub.size(); i++)
				pub_hashing.push_back(pub[i]);
			CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(pub_hashing, keyid);
			u = "Max Mustermann <max@moritz.de>";
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketUidEncode(u, uid);
			dsaflags.push_back(0x01);
			dsaflags.push_back(0x02);
			dsaflags.push_back(0x20);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepare(0x13, dsaflags, keyid, uidsig_hashing);
			ret = CallasDonnerhackeFinneyShawThayerRFC4880::CertificationHash(pub_hashing, u, uidsig_hashing, h, uidsig_left);
			assert(!ret);
			ret = gcry_sexp_build(&sigdata, &erroff, "(data (flags raw) (value %M))", h);
			assert(!ret);
			ret = gcry_pk_sign(&signature, sigdata, key);
			assert(!ret);
			ret = gcry_sexp_extract_param(signature, NULL, "rs", &r, &s, NULL);
			assert(!ret);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigEncode(uidsig_hashing, uidsig_left, r, s, uidsig);
			mpz_get_str(buffer, 16, vtmf->p);			
			ret = gcry_mpi_scan(&p, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
			assert(!ret); 
			mpz_get_str(buffer, 16, vtmf->g);			
			ret = gcry_mpi_scan(&g, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
			assert(!ret); 
			mpz_get_str(buffer, 16, vtmf->q);			
			ret = gcry_mpi_scan(&y, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
			assert(!ret);
			mpz_get_str(buffer, 16, vtmf->q);			
			ret = gcry_mpi_scan(&x, GCRYMPI_FMT_HEX, buffer, 0, &erroff);
			assert(!ret);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSubEncode(p, g, y, sub);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSsbEncode(p, g, y, x, ssb);
			elgflags.push_back(0x04);
			elgflags.push_back(0x10);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigPrepare(0x18, elgflags, keyid, subsig_hashing);
			for (size_t i = 6; i < sub.size(); i++)
				sub_hashing.push_back(sub[i]);
			CallasDonnerhackeFinneyShawThayerRFC4880::KeyidCompute(sub_hashing, subkeyid);
			ret = CallasDonnerhackeFinneyShawThayerRFC4880::SubkeyBindingHash(pub_hashing, sub_hashing, subsig_hashing, h, subsig_left);
			assert(!ret);
			ret = gcry_sexp_build(&sigdata, &erroff, "(data (flags raw) (value %M))", h);
			assert(!ret);
			ret = gcry_pk_sign(&signature, sigdata, key);
			assert(!ret);
			ret = gcry_sexp_extract_param(signature, NULL, "rs", &r, &s, NULL);
			assert(!ret);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSigEncode(subsig_hashing, subsig_left, r, s, subsig);
			// encrypt a message with this key
			m = "Das ist nur ein Test!";
			for (size_t i = 0; i < m.length(); i++)
				msg.push_back(m[i]);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketLitEncode(msg, lit);
			ret = CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricEncryptAES256(lit, seskey, prefix, true, enc);
			assert(!ret);
			mdc_hashing.insert(mdc_hashing.end(), prefix.begin(), prefix.end()); // "it includes the prefix data described above" [RFC4880]
			mdc_hashing.insert(mdc_hashing.end(), lit.begin(), lit.end()); // "it includes all of the plaintext" [RFC4880]
			mdc_hashing.push_back(0xD3); // "and the also includes two octets of values 0xD3, 0x14" [RFC4880]
			mdc_hashing.push_back(0x14);
			CallasDonnerhackeFinneyShawThayerRFC4880::HashCompute(2, mdc_hashing, hash); // "passed through the SHA-1 hash function" [RFC4880]
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketMdcEncode(hash, mdc);
			lit.insert(lit.end(), mdc.begin(), mdc.end());
			seskey.clear(); // generate a fresh session key
			ret = CallasDonnerhackeFinneyShawThayerRFC4880::SymmetricEncryptAES256(lit, seskey, prefix, false, enc2);
			assert(!ret);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSedEncode(enc, sed);
			assert(!ret);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketSeipdEncode(enc2, seipd);
			ret = gcry_sexp_build(&elgkey, &erroff, "(public-key (elg (p %M) (g %M) (y %M)))", p, g, y);
			assert(!ret);
			ret = CallasDonnerhackeFinneyShawThayerRFC4880::AsymmetricEncryptElgamal(seskey, elgkey, gk, myk);
			assert(!ret);
			CallasDonnerhackeFinneyShawThayerRFC4880::PacketPkeskEncode(subkeyid, gk, myk, pkesk);
			// export generated public key in OpenPGP armor format
			armor = "", all.clear();
			all.insert(all.end(), pub.begin(), pub.end());
			all.insert(all.end(), uid.begin(), uid.end());
			all.insert(all.end(), uidsig.begin(), uidsig.end());
			all.insert(all.end(), sub.begin(), sub.end());
			all.insert(all.end(), subsig.begin(), subsig.end());
			CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(6, all, armor);
			std::cout << armor << std::endl;
			// export generated private key in OpenPGP armor format
			armor = "", all.clear();
			all.insert(all.end(), sec.begin(), sec.end());
			all.insert(all.end(), uid.begin(), uid.end());
			all.insert(all.end(), uidsig.begin(), uidsig.end());
			all.insert(all.end(), ssb.begin(), ssb.end());
			all.insert(all.end(), subsig.begin(), subsig.end());
			CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(5, all, armor);
			std::cout << armor << std::endl;
			// export encrypted message in OpenPGP armor format (old-style format)
			armor = "", all.clear();
			all.insert(all.end(), pkesk.begin(), pkesk.end());
			all.insert(all.end(), sed.begin(), sed.end());
			CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(1, all, armor);
			std::cout << armor << std::endl;
			// export encrypted message in OpenPGP armor format (new-style format)
			armor = "", all.clear();
			all.insert(all.end(), pkesk.begin(), pkesk.end());
			all.insert(all.end(), seipd.begin(), seipd.end());
			all.insert(all.end(), mdc.begin(), mdc.end());
			CallasDonnerhackeFinneyShawThayerRFC4880::ArmorEncode(1, all, armor);
			std::cout << armor << std::endl;
			gcry_mpi_release(p);
			gcry_mpi_release(q);
			gcry_mpi_release(g);
			gcry_mpi_release(y);
			gcry_mpi_release(x);
			gcry_mpi_release(r);
			gcry_mpi_release(s);
			gcry_mpi_release(h);
			gcry_mpi_release(gk);
			gcry_mpi_release(myk);
			gcry_sexp_release(key);
			gcry_sexp_release(signature);
			gcry_sexp_release(sigdata);
			


}

int main
	(int argc, char **argv)
{
	assert(init_libTMCG());

	std::string line, armored_pubkey, message;

	std::cout << "Please provide the recipients DKG public key (in ASCII Armor): " << std::endl;
	while (std::getline(std::cin, line))
		armored_pubkey += line + "\r\n";
	std::cin.clear();

	BYTE atype = 0, ptag = 0xFF;
	OCTETS pkts;
	TMCG_OPENPGP_CONTEXT ctx;
	atype = CallasDonnerhackeFinneyShawThayerRFC4880::ArmorDecode(armored_pubkey, pkts);
	std::cout << "ArmorDecode() = " << (int)atype << std::endl;
	if (atype == 6)
	{
		while (pkts.size() && ptag)
		{
			ptag = CallasDonnerhackeFinneyShawThayerRFC4880::PacketDecode(pkts, ctx);
			std::cout << "PacketDecode() = " << (int)ptag;
			if (!ptag)
			{
				std::cerr << "ERROR: parsing OpenPGP packets failed" << std::endl;
				return -1; // error detected
			}
			std::cout << " version = " << (int)ctx.version;
			std::cout << std::endl;
			if (ptag == 13)
				std::cout << " uid = " << ctx.uid << std::endl;
		}
	}
	else
	{
		std::cerr << "ERROR: wrong type of ASCII Armor" << std::endl;
		return -1;
	}

	std::cout << "Now type your private message (in ASCII): " << std::endl;
	while (std::getline(std::cin, line))
		message += line + "\r\n";
	std::cin.clear();


	BarnettSmartVTMF_dlog 	*vtmf;
	std::stringstream 	crs;

	// create and check VTMF instance
	std::cout << "BarnettSmartVTMF_dlog()" << std::endl;
	vtmf = new BarnettSmartVTMF_dlog();
	std::cout << "vtmf.CheckGroup()" << std::endl;
	assert(vtmf->CheckGroup());
	
	// publish VTMF instance as string stream (common reference string)
	std::cout << "vtmf.PublishGroup(crs)" << std::endl;
	vtmf->PublishGroup(crs);
	
	
	// release VTMF instance
	delete vtmf;
	
	return 0;
}
