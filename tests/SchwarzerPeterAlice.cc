/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2005, 2006, 2007  Heiko Stamer <stamer@gaos.org>

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

// include the libTMCG header file
#include <libTMCG.hh>

// use Groth's efficient shuffle argument: p_cheating <= 2^{-TMCG_GROTH_L_E}
#define GROTH

int main
	()
{
	if (!init_libTMCG())
	{
		std::cerr << "Initialization of LibTMCG failed!" << std::endl;
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
	// finish the key generation
	vtmf->KeyGenerationProtocol_Finalize();
	
#ifdef GROTH
	// create an instance of Groth's shuffle argument for <= 25 cards
	GrothVSSHE *vsshe = new GrothVSSHE(25, vtmf->p, vtmf->q, vtmf->k, 
		vtmf->g, vtmf->h);
	vsshe->PublishGroup(std::cout);
	if (!vsshe->CheckGroup())
	{
		std::cerr << "Groth's shuffle argument was not sound!" << std::endl;
		return -1;
	}
	if (mpz_cmp(vtmf->h, vsshe->com->h))
	{
		std::cerr << "VSSHE: Common public key does not match!" << std::endl;
		return -1;
	}
	if (mpz_cmp(vtmf->q, vsshe->com->q))
	{
		std::cerr << "VSSHE: Subgroup order does not match!" << std::endl;
		return -1;
	}
	if (mpz_cmp(vtmf->p, vsshe->p) || mpz_cmp(vtmf->q, vsshe->q) || 
		mpz_cmp(vtmf->g, vsshe->g) || mpz_cmp(vtmf->h, vsshe->h))
	{
		std::cerr << "VSSHE: Encryption scheme does not match!" << std::endl;
		return -1;
	}
#endif
	
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
#ifdef GROTH
	tmcg->TMCG_ProveStackEquality_Groth(stack, stack_Alice, secret, vtmf,
		vsshe, std::cin, std::cout); // Groth's efficient shuffle argument
#else
	tmcg->TMCG_ProveStackEquality(stack, stack_Alice, secret, false, vtmf,
		std::cin, std::cout); // prove the correctness of the operation
#endif
	
	// ... Bob
	std::cin >> stack_Bob;
	if (!std::cin.good())
	{
		std::cerr << "Stack corrupted!" << std::endl;
		return -1;
	}
#ifdef GROTH
	if (!tmcg->TMCG_VerifyStackEquality_Groth(stack_Alice, stack_Bob, vtmf,
		vsshe, std::cin, std::cout)) // Groth's efficient shuffle argument
	{
		std::cerr << "StackEquality: proof of correctness failed!" << std::endl;
		return -1;
	}
#else
	if (!tmcg->TMCG_VerifyStackEquality(stack_Alice, stack_Bob, false, vtmf,
		std::cin, std::cout)) // verify the proof of correctness
	{
		std::cerr << "StackEquality: proof of correctness failed!" << std::endl;
		return -1;
	}
#endif
	
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
		// reveal the card type to the owner: Alice first, after it Bob.
		// -------------------------------------------------------------
		// The three operations SelfCardSecret(), VerifyCardSecret() and
		// TypeOfCard() MUST be called exactly in this order!
		TMCG_OpenStack<VTMF_Card> hand;
		size_t type = 0;
		
		// ... Alice
		std::cerr << "My cards are: ";
		for (size_t i = 0; i < hand_Alice.size(); i++)
		{
			tmcg->TMCG_SelfCardSecret(hand_Alice[i], vtmf);
			if (!tmcg->TMCG_VerifyCardSecret(hand_Alice[i], vtmf,
				std::cin, std::cout))
			{
				std::cerr << "CardSecret: proof of correctness failed!" << std::endl;
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
		
		// publish and draw a pair, if possible: Bob first, after it Alice.
		// ----------------------------------------------------------------
		size_t pairs = 0, lasttype = 0;
		
		// ... Bob
		std::cin >> pairs;
		std::cin.ignore(1, '\n'); // reject the newline
		if (pairs > 1)
		{
			std::cerr << "Bob wants to reveal more than one pair!" << std::endl;
			return -1;
		}
		if (pairs)
		{
			std::cerr << "Bob reveals: ";
			for (size_t i = 0; i < 2; i++)
			{
				VTMF_Card c;
				
				std::cin >> c;
				if (!std::cin.good())
				{
					std::cerr << "Card corrupted!" << std::endl;
					return -1;
				}
				// Check whether the card is in the stack.
				if (!hand_Bob.find(c))
				{
					std::cerr << "Bob does not own this card!" << std::endl;
					return -1;
				}
				// Reveal the card and verify the proof of correctness.
				tmcg->TMCG_SelfCardSecret(c, vtmf);
				if (!tmcg->TMCG_VerifyCardSecret(c, vtmf, std::cin, std::cout))
				{
					std::cerr << "CardSecret: proof of correctness failed!" << std::endl;
					return -1;
				}
				type = tmcg->TMCG_TypeOfCard(c, vtmf);
				// Check whether it is really a pair.
				if (i % 2)
				{
					if (lasttype != type)
					{
						std::cerr << "Bob reveals no pair!" << std::endl;
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
		// Send the number of pairs to Bob.
		std::cout << (pairstack.size() / 2) << std::endl;
		// Reveal the pairs, prove the correctness and remove them from our hand.
		if (pairstack.size() > 0)
		{
			std::cerr << "My pairs to reveal: ";
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
		
		// Cleanup and check the game outcome.
		// -----------------------------------
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
		
		// Draw a private card from the opponent: Only the player who have
		// fewer cards will draw. After the draw the hand is shuffled again.
		// -----------------------------------------------------------------
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
				// ... Alice
				position = mpz_srandom_mod(hand_Bob.size());
				std::cout << position << std::endl;
				c = hand_Bob[position]; // draw a card
				hand_Bob.remove(c); // remove it
				tmcg->TMCG_SelfCardSecret(c, vtmf); // reveal it privatly
				if (!tmcg->TMCG_VerifyCardSecret(c, vtmf, std::cin, std::cout))
				{
					std::cerr << "CardSecret: proof of correctness failed!" << std::endl;
					return -1;
				}
				type = tmcg->TMCG_TypeOfCard(c, vtmf);
				std::cerr << "Alice draws the card (from position " << position <<
					"): " << type;
				if (type)
					std::cerr << std::endl;
				else
					std::cerr << " (Zonk!)" << std::endl;
				hand_Alice.push(c); // push it to Alice's hand
				// shuffle, because Bob must not know the position of the drawed card
				tmcg->TMCG_CreateStackSecret(secret, false, hand_Alice.size(), vtmf);
				tmcg->TMCG_MixStack(hand_Alice, stack_Alice, secret, vtmf);
				std::cout << stack_Alice << std::endl; // send the result to Bob
#ifdef GROTH
				tmcg->TMCG_ProveStackEquality_Groth(hand_Alice, stack_Alice, secret,
					vtmf, vsshe, std::cin, std::cout);
#else
				tmcg->TMCG_ProveStackEquality(hand_Alice, stack_Alice, secret, false,
					vtmf, std::cin, std::cout);
#endif
				hand_Alice = stack_Alice;
			}
			else
			{
				// ... Bob
				std::cin >> position;
				std::cin.ignore(1, '\n'); // reject the newline
				if (position >= hand_Alice.size())
				{
					std::cerr << "Bob wants to draw from a wrong position!" << std::endl;
					return -1;
				}
				c = hand_Alice[position]; // draw a card
				hand_Alice.remove(c); // remove it
				tmcg->TMCG_ProveCardSecret(c, vtmf, std::cin, std::cout); // revealing
				hand_Bob.push(c); // push it to Bob's hand
				// shuffle, because Alice must not know the position of the drawed card
				std::cin >> stack_Bob;
				if (!std::cin.good())
				{
					std::cerr << "Stack corrupted!" << std::endl;
					return -1;
				}
#ifdef GROTH
				if (!tmcg->TMCG_VerifyStackEquality_Groth(hand_Bob, stack_Bob, vtmf,
					vsshe, std::cin, std::cout)) // verify Groth's shuffle argument
				{
					std::cerr << "StackEquality: proof of correctness failed!" << std::endl;
					return -1;
				}
#else
				if (!tmcg->TMCG_VerifyStackEquality(hand_Bob, stack_Bob, false, vtmf,
					std::cin, std::cout)) // verify the proof of correctness
				{
					std::cerr << "StackEquality: proof of correctness failed!" << std::endl;
					return -1;
				}
#endif
				hand_Bob = stack_Bob;
			}
		}
	}
	
	// final cleanup
#ifdef GROTH
	delete vsshe;
#endif
	delete vtmf, delete tmcg;
}
