// include the libTMCG header file
#include <libTMCG.hh>

int main
	()
{
	if (!init_libTMCG())
	{
		std::cerr << "Initalization of the libTMCG failed!" << std::endl;
		return -1;
	}
	
	// create an instance of the "Toolbox for Mental Card Games"
	// --------------------------------------------------------
	// p_cheating <= 2^{-16}, k = 2 players, w = 4 bits (2^4 >= 13 card types)
	size_t t = 16, k = 2, w = 4;
	SchindelhauerTMCG *tmcg = new SchindelhauerTMCG(t, k, w);
	
	// create an instance of the VTMF implementation (create the group G)
	BarnettSmartVTMF_dlog *vtmf = new BarnettSmartVTMF_dlog();
	// check whether the group G was correctly generated
	if (!vtmf->CheckGroup())
	{
		std::cerr << "Group G was not correctly generated!" << std::endl;
		return -1;
	}
	// send the parameters of the group to Bob (the second party)
	vtmf->PublishGroup(std::cout);
	// create and send the (public) key
	vtmf->KeyGenerationProtocol_GenerateKey();
	vtmf->KeyGenerationProtocol_PublishKey(std::cout);
	// receive Bob's public key and update the VTMF implementation
	if (!vtmf->KeyGenerationProtocol_UpdateKey(std::cin))
	{
		std::cerr << "Bob's public key was not correctly generated!" << std::endl;
		return -1;
	}
	
	// create a deck of 25 cards (12 pairs and the "Schwarzer Peter")
	// --------------------------------------------------------------
	std::cerr << "Create the deck ..." << std::endl;
	TMCG_OpenStack<VTMF_Card> deck;
	for (size_t i = 0; i < 13; i++)
	{
		for (size_t j = 0; j < 2; (i != 0) ? j++ : j = 2)
		{
			VTMF_Card c;
			tmcg->TMCG_CreateOpenCard(c, vtmf, i); // create a card of type i
			deck.push(i, c);      // push this card to the open stack deck
		}
	}
	
	// shuffle the deck: Alice first, after it Bob.
	// --------------------------------------------
	std::cerr << "Shuffle the deck ..." << std::endl;
	TMCG_Stack<VTMF_Card> stack, stack_Alice, stack_Bob;
	TMCG_StackSecret<VTMF_CardSecret> secret;
	stack.push(deck); // push the whole deck to the working stack
	// create the secret for a full shuffle (permutation) of the stack
	tmcg->TMCG_CreateStackSecret(secret, false, stack.size(), vtmf);
	
	// ... Alice
	tmcg->TMCG_MixStack(stack, stack_Alice, secret, vtmf); // shuffle operation
	std::cout << stack_Alice << std::endl; // send the result to Bob
	tmcg->TMCG_ProveStackEquality(stack, stack_Alice, secret, false, vtmf,
		std::cin, std::cout); // prove the correctness of the operation
	
	// ... Bob
	char *tmp = new char[TMCG_MAX_STACK_CHARS];
	std::cin.getline(tmp, TMCG_MAX_STACK_CHARS);
	if (!stack_Bob.import(tmp))
	{
		std::cerr << "Stack corrupted!" << std::endl;
		return -1;
	}
	if (!tmcg->TMCG_VerifyStackEquality(stack_Alice, stack_Bob, false, vtmf,
		std::cin, std::cout)) // verify the proof of correctness
	{
		std::cerr << "Proof of correctness wrong!" << std::endl;
		return -1;
	}
	
	// dealing: Alice gets the 1st to 13th and Bob the remaining cards.
	// ----------------------------------------------------------------
	std::cerr << "Deal the cards ..." << std::endl;
	TMCG_Stack<VTMF_Card> hand_Alice, hand_Bob;
	for (size_t i = 0; i < 13 ; i++)
		hand_Alice.push(stack_Bob[i]);
	for (size_t i = 13; i < 25 ; i++)
		hand_Bob.push(stack_Bob[i]);
	
	// The real game proceeds like an endless loop.
	// --------------------------------------------
	while (1)
	{
		// Handkarten privat aufdecken: Alice zuerst, dann Bob.
		// ----------------------------------------------------
		// Die drei Operationen SelfCardSecret, VerifyCardSecret und
		// TypeOfCard müssen in *genau* dieser Reihenfolge aufgerufen werden!
		TMCG_OpenStack<VTMF_Card> hand;
		size_t type = 0;
		
		// ... Alice
		std::cerr << "Meine Karten: ";
		for (size_t i = 0; i < hand_Alice.size(); i++)
		{
			tmcg->TMCG_SelfCardSecret(hand_Alice[i], vtmf);
			if (!tmcg->TMCG_VerifyCardSecret(hand_Alice[i], vtmf,
				std::cin, std::cout))
			{
				std::cerr << ">< Öffnungsbeweis falsch (Betrugsversuch?)" <<
					std::endl;
				return -1;
			}
			type = tmcg->TMCG_TypeOfCard(hand_Alice[i], vtmf);
			hand.push(type, hand_Alice[i]);
			std::cerr << type << " ";
		}
		std::cerr << std::endl;
		
		// ... Bob
		for (size_t i = 0; i < hand_Bob.size(); i++)
			tmcg->TMCG_ProveCardSecret(hand_Bob[i], vtmf, std::cin, std::cout);
		
		// Ein Paar offen ablegen (sofern möglich): Bob zuerst, dann Alice.
		// ----------------------------------------------------------------
		size_t pairs = 0, lasttype = 0;
		
		// ... Bob
		std::cin >> pairs;
		std::cin.ignore(1, '\n'); // reject the newline
		if (pairs > 1)
		{
			std::cerr << ">< Unerlaubte Paaranzahl (Trollversuch?)" << std::endl;
			return -1;
		}
		if (pairs)
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
				if (!hand_Bob.find(c))
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
				type = tmcg->TMCG_TypeOfCard(c, vtmf);
				// Prüfen, ob wirklich ein Paar vorliegt
				if (i % 2)
				{
					if (lasttype != type)
					{
						std::cerr << ">< Kein Paar (Trollversuch?)" << std::endl;
						return -1;
					}
					else
						std::cerr << type << " ";
				}
				else
					lasttype = type;
				hand_Bob.remove(c); // remove the card from Bob's hand
			}
			std::cerr << std::endl;
		}
		
		// .. Alice
		TMCG_OpenStack<VTMF_Card> pairstack;
		// search for pairs
		for (size_t i = 0; i < hand.size(); i++)
		{
			for (size_t j = 0; j < hand.size(); j++)
			{
				// pair found?
				if ((i < j) && (hand[i].first == hand[j].first))
				{
					pairstack.push(hand[i]), pairstack.push(hand[j]);
					i = hand.size(); // break the search
					break;
				}
			}
		}
		// Anzahl senden, Paare aufdecken und entfernen
		std::cout << (pairstack.size() / 2) << std::endl;
		if (pairstack.size() > 0)
		{
			std::cerr << "Ich lege ab: ";
			for (size_t i = 0; i < pairstack.size(); i++)
			{
				std::cout << pairstack[i].second << std::endl;
				tmcg->TMCG_ProveCardSecret(pairstack[i].second, vtmf,
					std::cin, std::cout);
				hand_Alice.remove(pairstack[i].second);
				hand.remove(pairstack[i].first);
				if (i % 2)
					std::cerr << pairstack[i].first << " ";
			}
			std::cerr << std::endl;
		}
		
		// Aufräumen und Abbruchkriterium prüfen
		// -------------------------------------
		pairstack.clear(), stack_Alice.clear(), stack_Bob.clear();
		if (hand_Alice.size() == 0)
		{
			std::cerr << "You win the game!" << std::endl;
			break;
		}
		if (hand_Bob.size() == 0)
		{
			std::cerr << ">< You loose. Zonk! ('Schwarzer Peter')" << std::endl;
			break;
		}
		
		// Eine Karte beim Gegner ziehen: Der mit weniger Karten zieht.
		// Nach dem Ziehen wird neu gemischt und die Korrektheit gezeigt.
		// --------------------------------------------------------------
		size_t position;
		std::vector<bool> who;
		VTMF_Card c;
		
		if (hand_Alice.size() > hand_Bob.size())
			who.push_back(false);
		else
			who.push_back(true);
		
		for (size_t i = 0; i < who.size(); i++)
		{
			if (who[i])
			{
				// Alice zieht ...
				position = mpz_srandom_ui() % hand_Bob.size();
				std::cout << position << std::endl;
				c = hand_Bob[position]; // Karte holen, ...
				hand_Bob.remove(c);           // entfernen, ...
				tmcg->TMCG_SelfCardSecret(c, vtmf);   // aufdecken, ...
				if (!tmcg->TMCG_VerifyCardSecret(c, vtmf, std::cin, std::cout))
				{
					std::cerr << ">< Öffnungsbeweis falsch (Betrugsversuch?)" <<
						std::endl;
					return -1;
				}
				type = tmcg->TMCG_TypeOfCard(c, vtmf);
				std::cerr << "Ich ziehe die Karte (von Position " << position <<
					"): " << type;
				if (type)
					std::cerr << std::endl;
				else
					std::cerr << " (Zonk!)" << std::endl;
				hand_Alice.push(c); // ... und auf Alices Stapel legen.
				// ... und mischt neu.
				tmcg->TMCG_CreateStackSecret(secret, false, hand_Alice.size(), vtmf);
				tmcg->TMCG_MixStack(hand_Alice, stack_Alice, secret, vtmf);
				std::cout << stack_Alice << std::endl; // send the result to Bob
				tmcg->TMCG_ProveStackEquality(hand_Alice, stack_Alice, secret, false,
					vtmf, std::cin, std::cout);
				hand_Alice = stack_Alice;
			}
			else
			{
				// Bob zieht ...
				std::cin >> position;
				std::cin.ignore(1, '\n'); // reject the newline
				if (position >= hand_Alice.size())
				{
					std::cerr << ">< Falscher Index (Trollversuch?)" << std::endl;
					return -1;
				}
				c = hand_Alice[position]; // Karte holen,
				hand_Alice.remove(c); // entfernen,
				tmcg->TMCG_ProveCardSecret(c, vtmf, std::cin, std::cout); // aufdecken,
				hand_Bob.push(c);               // ... und auf Bobs Stapel legen.
				// ... und mischt neu.
				char *tmp = new char[TMCG_MAX_STACK_CHARS];
				std::cin.getline(tmp, TMCG_MAX_STACK_CHARS);
				if (!stack_Bob.import(tmp))
				{
					std::cerr << ">< Stapelformat falsch (Trollversuch?)" << std::endl;
					return -1;
				}
				if (!tmcg->TMCG_VerifyStackEquality(hand_Bob, stack_Bob, false, vtmf,
					std::cin, std::cout)) // verify the proof of correctness
				{
					std::cerr << ">< Stapelbeweis falsch (Betrugsversuch?)" << std::endl;
					return -1;
				}
				hand_Bob = stack_Bob;
			}
		}
	}
	
	// cleanup
	delete vtmf, delete tmcg;
}
