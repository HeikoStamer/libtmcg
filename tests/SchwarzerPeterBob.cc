// libTMCG
#include <libTMCG.hh>

int main
	()
{
	if (!init_libTMCG())
		exit(-1);

	// Initalisieren der "Toolbox for Mental Card Games"
	// -------------------------------------------------
	size_t t = 16, k = 2, w = 4; // p_Betrug <= 2^{-16}, 2 Spieler, 13 Typen
	SchindelhauerTMCG *tmcg = new SchindelhauerTMCG(t, k, w);
	
	// Initalisieren und Überprüfen der Gruppe G (von Alice erzeugt)
	BarnettSmartVTMF_dlog *vtmf = new BarnettSmartVTMF_dlog(std::cin);
	if (!vtmf->CheckGroup())
	{
		std::cerr << ">< Gruppe G fehlerhaft erzeugt" << std::endl;
		return -1;
	}
	
	// Erzeugen und Senden des eigenen VTMF-Schlüssels
	vtmf->KeyGenerationProtocol_GenerateKey();
	vtmf->KeyGenerationProtocol_PublishKey(std::cout);
	// Einfügen von Alice's Schlüssel
	if (!vtmf->KeyGenerationProtocol_UpdateKey(std::cin))
	{
		std::cerr << ">< Schlüsselbeweis falsch" << std::endl;
		return -1;
	}
	
	// Blatt mit 25 Karten erstellen (12 Paare und ein "Schwarzer Peter")
	// ------------------------------------------------------------------
	TMCG_OpenStack<VTMF_Card> Anfangsstapel;
	for (size_t i = 0; i < 13; i++)
	{
		for (size_t j = 0; j < 2; (i != 0) ? j++ : j = 2)
		{
			VTMF_Card c;
			tmcg->TMCG_CreateOpenCard(c, vtmf, i); // Karte mit Typ i erzeugen,
			Anfangsstapel.push(i, c);      // und auf den offenen Stapel legen.
		}
	}
	
	// Anfangsstapel mischen: Alice zuerst, dann Bob.
	// ----------------------------------------------
	std::cerr << "Anfangsstapel mischen ..." << std::endl;
	TMCG_Stack<VTMF_Card> Mischstapel, Mischstapel_Alice, Mischstapel_Bob;
	TMCG_StackSecret<VTMF_CardSecret> Mischgeheimnis;
	Mischstapel.push(Anfangsstapel); // offenen in allgemeinen Stapel umwandeln
	tmcg->TMCG_CreateStackSecret(Mischgeheimnis, false, // volle Permutation
		Mischstapel.size(), vtmf);
	
	// ... Alice
	char *tmp = new char[TMCG_MAX_STACK_CHARS];
	std::cin.getline(tmp, TMCG_MAX_STACK_CHARS);
	if (!Mischstapel_Alice.import(tmp))
	{
		std::cerr << ">< Stapelformat falsch (Trollversuch?)" << std::endl;
		return -1;
	}
	if (!tmcg->TMCG_VerifyStackEquality(Mischstapel, Mischstapel_Alice,
		false, vtmf, std::cin, std::cout))
	{
		std::cerr << ">< Stapelbeweis falsch (Betrugsversuch?)" << std::endl;
		return -1;
	}
	// ... Bob
	tmcg->TMCG_MixStack(Mischstapel_Alice, Mischstapel_Bob,
		Mischgeheimnis, vtmf);                             // Maskieren
	std::cout << Mischstapel_Bob << std::endl;             // Stapel an Alice senden
	tmcg->TMCG_ProveStackEquality(Mischstapel_Alice, Mischstapel_Bob,
		Mischgeheimnis, false, vtmf, std::cin, std::cout); // Korrektheit beweisen
	
	// Stapel teilen: Alice erhält die Karten 1 bis 13 und Bob den Rest.
	// -----------------------------------------------------------------
	std::cerr << "Stapel teilen ..." << std::endl;
	TMCG_Stack<VTMF_Card> Kartenstapel_Alice, Kartenstapel_Bob;
	for (size_t i = 0; i < 13 ; i++)
		Kartenstapel_Alice.push(Mischstapel_Bob[i]);
	for (size_t i = 13; i < 25 ; i++)
		Kartenstapel_Bob.push(Mischstapel_Bob[i]);
	
	// Das eigentliche Spiel läuft in einer (Endlos-)Schleife.
	// -------------------------------------------------------
	while (1)
	{
		// Handkarten privat aufdecken: Alice zuerst, dann Bob.
		// ----------------------------------------------------
		// Die drei Operationen SelfCardSecret, VerifyCardSecret und
		// TypeOfCard müssen in *genau* dieser Reihenfolge aufgerufen werden!
		TMCG_OpenStack<VTMF_Card> Handkarten;
		size_t Typ = 0;
		
		// ... Alice
		for (size_t i = 0; i < Kartenstapel_Alice.size(); i++)
		{
			tmcg->TMCG_ProveCardSecret(Kartenstapel_Alice[i], vtmf,
				std::cin, std::cout);
		}
		
		// ... Bob
		std::cerr << "Meine Karten: ";
		for (size_t i = 0; i < Kartenstapel_Bob.size(); i++)
		{
			tmcg->TMCG_SelfCardSecret(Kartenstapel_Bob[i], vtmf);
			if (!tmcg->TMCG_VerifyCardSecret(Kartenstapel_Bob[i], vtmf,
				std::cin, std::cout))
			{
				std::cerr << ">< Öffnungsbeweis falsch (Betrugsversuch?)" <<
					std::endl;
				return -1;
			}
			Typ = tmcg->TMCG_TypeOfCard(Kartenstapel_Bob[i], vtmf);
			Handkarten.push(Typ, Kartenstapel_Bob[i]);
			std::cerr << Typ << " ";
		}
		std::cerr << std::endl;
		
		// Ein Paar offen ablegen (sofern möglich): Bob zuerst, dann Alice.
		// ----------------------------------------------------------------
		TMCG_OpenStack<VTMF_Card> Paarstapel;
		size_t Paare = 0, LetzterTyp = 0;
		
		// ... Bob
		// Paare suchen
		for (size_t i = 0; i < Handkarten.size(); i++)
		{
			for (size_t j = 0; j < Handkarten.size(); j++)
			{
				// Paar gefunden?
				if ((i < j) &&
					(Handkarten[i].first == Handkarten[j].first))
				{
					Paarstapel.push(Handkarten[i]);
					Paarstapel.push(Handkarten[j]);
					i = Handkarten.size();          // keine weiteren Paare suchen
					break;
				}
			}
		}
		// Anzahl senden, Paare aufdecken und entfernen
		std::cout << (Paarstapel.size() / 2) << std::endl;
		if (Paarstapel.size())
		{
			std::cerr << "Ich lege ab: ";
			for (size_t i = 0; i < Paarstapel.size(); i++)
			{
				std::cout << Paarstapel[i].second << std::endl;
				tmcg->TMCG_ProveCardSecret(Paarstapel[i].second, vtmf,
					std::cin, std::cout);
				Kartenstapel_Bob.remove(Paarstapel[i].second);
				Handkarten.remove(Paarstapel[i].first);
				if (i % 2)
					std::cerr << Paarstapel[i].first << " ";
			}
			std::cerr << std::endl;
		}
		
		// ... Alice
		std::cin >> Paare;
		std::cin.ignore(1, '\n'); // Newline verwerfen
		if (Paare > 1)
		{
			std::cerr << ">< Unerlaubte Paaranzahl (Trollversuch?)" << std::endl;
			return -1;
		}
		if (Paare)
		{
			std::cerr << "Gegner legt ab: ";
			for (size_t i = 0; i < 2; i++)
			{
				VTMF_Card c;
				char *tmp = new char[TMCG_MAX_CARD_CHARS];
				std::cin.getline(tmp, TMCG_MAX_CARD_CHARS);
				if (!c.import(tmp))
				{
					std::cerr << ">< Kartenformat falsch (Trollversuch?)" <<
						std::endl;
					return -1;
				}
				// Prüfen, ob Karte im Stapel ist
				if (!Kartenstapel_Alice.find(c))
				{
					std::cerr << ">< Karte nicht vorhanden (Betrugsversuch?)" <<
						std::endl;
					return -1;
				}
				// Karte aufdecken und Korrektheit prüfen
				tmcg->TMCG_SelfCardSecret(c, vtmf);
				if (!tmcg->TMCG_VerifyCardSecret(c, vtmf, std::cin, std::cout))
				{
					std::cerr << ">< Öffnungsbeweis falsch (Betrugsversuch?)" <<
						std::endl;
					return -1;
				}
				Typ = tmcg->TMCG_TypeOfCard(c, vtmf);
				// Prüfen, ob wirklich ein Paar vorliegt
				if (i % 2)
				{
					if (LetzterTyp != Typ)
					{
						std::cerr << ">< Kein Paar (Trollversuch?)" << std::endl;
						return -1;
					}
					else
						std::cerr << Typ << " ";
				}
				else
					LetzterTyp = Typ;
				// Karte entfernen
				Kartenstapel_Alice.remove(c);
			}
			std::cerr << std::endl;
		}
		
		// Aufräumen und Abbruchkriterium prüfen
		// -------------------------------------
		Paarstapel.clear();
		Mischstapel_Alice.clear(), Mischstapel_Bob.clear();
		if (Kartenstapel_Alice.size() == 0)
		{
			std::cerr << ">< Zonk! ('Schwarzer Peter')" << std::endl;
			break;
		}
		if (Kartenstapel_Bob.size() == 0)
		{
			std::cerr << ">< Glück gehabt!" << std::endl;
			break;
		}
		
		// Eine Karte beim Gegner ziehen: Der mit weniger Karten zieht.
		// Nach dem Ziehen wird neu gemischt und die Korrektheit gezeigt.
		// --------------------------------------------------------------
		size_t WelchePosition;
		std::vector<bool> Ablauf;
		VTMF_Card c;
		
		if (Kartenstapel_Alice.size() > Kartenstapel_Bob.size())
			Ablauf.push_back(true);
		else
			Ablauf.push_back(false);
		
		for (size_t i = 0; i < Ablauf.size(); i++)
		{
			if (Ablauf[i])
			{
				// Bob zieht ...
				WelchePosition = mpz_srandom_ui() % Kartenstapel_Alice.size();
				std::cout << WelchePosition << std::endl;
				c = Kartenstapel_Alice[WelchePosition]; // Karte holen, ...
				Kartenstapel_Alice.remove(c);           // entfernen, ...
				tmcg->TMCG_SelfCardSecret(c, vtmf);     // aufdecken, ...
				if (!tmcg->TMCG_VerifyCardSecret(c, vtmf, std::cin, std::cout))
				{
					std::cerr << ">< Öffnungsbeweis falsch (Betrugsversuch?)" <<
						std::endl;
					return -1;
				}
				Typ = tmcg->TMCG_TypeOfCard(c, vtmf);
				std::cerr << "Ich ziehe die Karte (von Position " <<
					WelchePosition << "): " << Typ;
				if (Typ)
					std::cerr << std::endl;
				else
					std::cerr << " (Zonk!)" << std::endl;
				Kartenstapel_Bob.push(c); // ... und auf Bobs Stapel legen.
				// ... und mischt neu.
				tmcg->TMCG_CreateStackSecret(Mischgeheimnis, false,
					Kartenstapel_Bob.size(), vtmf);
				tmcg->TMCG_MixStack(Kartenstapel_Bob, Mischstapel_Bob,
					Mischgeheimnis, vtmf);                             // Maskieren, ...
				std::cout << Mischstapel_Bob << std::endl;           // senden, ...
				tmcg->TMCG_ProveStackEquality(Kartenstapel_Bob, Mischstapel_Bob,
					Mischgeheimnis, false, vtmf, std::cin, std::cout); // beweisen.
				Kartenstapel_Bob = Mischstapel_Bob;
			}
			else
			{
				// Alice zieht ...
				std::cin >> WelchePosition;
				std::cin.ignore(1, '\n'); // Newline verwerfen
				if (WelchePosition >= Kartenstapel_Bob.size())
				{
					std::cerr << ">< Falscher Index (Trollversuch?)" << std::endl;
					return -1;
				}
				c = Kartenstapel_Bob[WelchePosition];        // Karte holen, ...
				Kartenstapel_Bob.remove(c);                  // entfernen, ...
				tmcg->TMCG_ProveCardSecret(c, vtmf, std::cin, std::cout); // aufdecken,
				Kartenstapel_Alice.push(c); // ... und auf Alices Stapel legen.
				// ... und mischt neu.
				char *tmp = new char[TMCG_MAX_STACK_CHARS];
				std::cin.getline(tmp, TMCG_MAX_STACK_CHARS);
				if (!Mischstapel_Alice.import(tmp))
				{
					std::cerr << ">< Stapelformat falsch (Trollversuch?)" << std::endl;
					return -1;
				}
				if (!tmcg->TMCG_VerifyStackEquality(Kartenstapel_Alice,
					Mischstapel_Alice, false, vtmf, std::cin, std::cout)) // verifizieren
				{
					std::cerr << ">< Stapelbeweis falsch (Betrugsversuch?)" << std::endl;
					return -1;
				}
				Kartenstapel_Alice = Mischstapel_Alice;
			}
		}
	}
	
	// Aufräumen
	delete vtmf, delete tmcg;
}
