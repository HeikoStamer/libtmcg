// include the libTMCG header file
#include <libTMCG.hh>

int main
	()
{
	if (!init_libTMCG())
	{
		std::cerr << _("Initalization of the libTMCG failed!") << std::endl;
		return -1;
	}
	
	// create a instance of the "Toolbox for Mental Card Games"
	// --------------------------------------------------------
	// p_cheating <= 2^{-16}, k = 2 players, w = 4 bits (2^4 >= 13 different cards)
	size_t t = 16, k = 2, w = 4;
	SchindelhauerTMCG *tmcg = new SchindelhauerTMCG(t, k, w);
		
	// create a instance of the VTMF implementation (create the group G)
	BarnettSmartVTMF_dlog *vtmf = new BarnettSmartVTMF_dlog();
	// check whether the group G was correctly generated
	if (!vtmf->CheckGroup())
	{
		std::cerr << _("Group G was not correctly generated!") << std::endl;
		return -1;
	}
	// send the parameters of the group to Bob (second party)
	vtmf->PublishGroup(std::cout);
	// create and send the (public) key
	vtmf->KeyGenerationProtocol_GenerateKey();
	vtmf->KeyGenerationProtocol_PublishKey(std::cout);
	// receive Bob's public key and update the VTMF implementation
	if (!vtmf->KeyGenerationProtocol_UpdateKey(std::cin))
	{
		std::cerr << _("Bob's public key was not correctly generated!") << std::endl;
		return -1;
	}
	
	// create a deck of 25 cards (12 pairs and one "Schwarzer Peter")
	// --------------------------------------------------------------
	TMCG_OpenStack<VTMF_Card> Anfangsstapel;
	for (size_t i = 0; i < 13; i++)
	{
		for (size_t j = 0; j < 2; (i != 0) ? j++ : j = 2)
		{
			VTMF_Card c;
			tmcg->TMCG_CreateOpenCard(c, vtmf, i); // create a card of type i
			Anfangsstapel.push(i, c);      // push this card to the open stack
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
	tmcg->TMCG_MixStack(Mischstapel, Mischstapel_Alice,
		Mischgeheimnis, vtmf);                             // Maskieren
	std::cout << Mischstapel_Alice << std::endl;           // Stapel an Bob senden
	tmcg->TMCG_ProveStackEquality(Mischstapel, Mischstapel_Alice,
		Mischgeheimnis, false, vtmf, std::cin, std::cout); // Korrektheit beweisen
	
	// ... Bob
	char *tmp = new char[TMCG_MAX_STACK_CHARS];
	std::cin.getline(tmp, TMCG_MAX_STACK_CHARS);
	if (!Mischstapel_Bob.import(tmp))
	{
		std::cerr << ">< Stapelformat falsch (Trollversuch?)" << std::endl;
		return -1;
	}
	if (!tmcg->TMCG_VerifyStackEquality(Mischstapel_Alice,
		Mischstapel_Bob, false, vtmf, std::cin, std::cout)) // Beweis verifizieren
	{
		std::cerr << ">< Stapelbeweis falsch (Betrugsversuch?)" << std::endl;
		return -1;
	}
	
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
		std::cerr << "Meine Karten: ";
		for (size_t i = 0; i < Kartenstapel_Alice.size(); i++)
		{
			tmcg->TMCG_SelfCardSecret(Kartenstapel_Alice[i], vtmf);
			if (!tmcg->TMCG_VerifyCardSecret(Kartenstapel_Alice[i], vtmf,
				std::cin, std::cout))
			{
				std::cerr << ">< Öffnungsbeweis falsch (Betrugsversuch?)" <<
					std::endl;
				return -1;
			}
			Typ = tmcg->TMCG_TypeOfCard(Kartenstapel_Alice[i], vtmf);
			Handkarten.push(Typ, Kartenstapel_Alice[i]);
			std::cerr << Typ << " ";
		}
		std::cerr << std::endl;
		
		// ... Bob
		for (size_t i = 0; i < Kartenstapel_Bob.size(); i++)
		{
			tmcg->TMCG_ProveCardSecret(Kartenstapel_Bob[i], vtmf,
				std::cin, std::cout);
		}
		
		// Ein Paar offen ablegen (sofern möglich): Bob zuerst, dann Alice.
		// ----------------------------------------------------------------
		TMCG_OpenStack<VTMF_Card> Paarstapel;
		size_t Paare = 0, LetzterTyp = 0;
		
		// ... Bob
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
				if (!Kartenstapel_Bob.find(c))
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
				Kartenstapel_Bob.remove(c);
			}
			std::cerr << std::endl;
		}
		
		// .. Alice
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
				Kartenstapel_Alice.remove(Paarstapel[i].second);
				Handkarten.remove(Paarstapel[i].first);
				if (i % 2)
					std::cerr << Paarstapel[i].first << " ";
			}
			std::cerr << std::endl;
		}
		
		// Aufräumen und Abbruchkriterium prüfen
		// -------------------------------------
		Paarstapel.clear();
		Mischstapel_Alice.clear(), Mischstapel_Bob.clear();
		if (Kartenstapel_Alice.size() == 0)
		{
			std::cerr << ">< Glück gehabt!" << std::endl;
			break;
		}
		if (Kartenstapel_Bob.size() == 0)
		{
			std::cerr << ">< Zonk! ('Schwarzer Peter')" << std::endl;
			break;
		}
		
		// Eine Karte beim Gegner ziehen: Der mit weniger Karten zieht.
		// Nach dem Ziehen wird neu gemischt und die Korrektheit gezeigt.
		// --------------------------------------------------------------
		size_t WelchePosition;
		std::vector<bool> Ablauf;
		VTMF_Card c;
		
		if (Kartenstapel_Alice.size() > Kartenstapel_Bob.size())
			Ablauf.push_back(false);
		else
			Ablauf.push_back(true);
		
		for (size_t i = 0; i < Ablauf.size(); i++)
		{
			if (Ablauf[i])
			{
				// Alice zieht ...
				WelchePosition = mpz_srandom_ui() % Kartenstapel_Bob.size();
				std::cout << WelchePosition << std::endl;
				c = Kartenstapel_Bob[WelchePosition]; // Karte holen, ...
				Kartenstapel_Bob.remove(c);           // entfernen, ...
				tmcg->TMCG_SelfCardSecret(c, vtmf);   // aufdecken, ...
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
				Kartenstapel_Alice.push(c); // ... und auf Alices Stapel legen.
				// ... und mischt neu.
				tmcg->TMCG_CreateStackSecret(Mischgeheimnis, false,
					Kartenstapel_Alice.size(), vtmf);
				tmcg->TMCG_MixStack(Kartenstapel_Alice, Mischstapel_Alice,
					Mischgeheimnis, vtmf);                             // Maskieren, ...
				std::cout << Mischstapel_Alice << std::endl;         // senden, ...
				tmcg->TMCG_ProveStackEquality(Kartenstapel_Alice, Mischstapel_Alice,
				Mischgeheimnis, false, vtmf, std::cin, std::cout); // beweisen.
				Kartenstapel_Alice = Mischstapel_Alice;
			}
			else
			{
				// Bob zieht ...
				std::cin >> WelchePosition;
				std::cin.ignore(1, '\n'); // Newline verwerfen
				if (WelchePosition >= Kartenstapel_Alice.size())
				{
					std::cerr << ">< Falscher Index (Trollversuch?)" << std::endl;
					return -1;
				}
				c = Kartenstapel_Alice[WelchePosition]; // Karte holen,
				Kartenstapel_Alice.remove(c);           // entfernen,
				tmcg->TMCG_ProveCardSecret(c, vtmf, std::cin, std::cout); // aufdecken,
				Kartenstapel_Bob.push(c);               // ... und auf Bobs Stapel legen.
				// ... und mischt neu.
				char *tmp = new char[TMCG_MAX_STACK_CHARS];
				std::cin.getline(tmp, TMCG_MAX_STACK_CHARS);
				if (!Mischstapel_Bob.import(tmp))
				{
					std::cerr << ">< Stapelformat falsch (Trollversuch?)" << std::endl;
					return -1;
				}
				if (!tmcg->TMCG_VerifyStackEquality(Kartenstapel_Bob,
					Mischstapel_Bob, false, vtmf, std::cin, std::cout)) // verifizieren
				{
					std::cerr << ">< Stapelbeweis falsch (Betrugsversuch?)" << std::endl;
					return -1;
				}
				Kartenstapel_Bob = Mischstapel_Bob;
			}
		}
	}
	
	// Aufräumen
	delete vtmf, delete tmcg;
}
