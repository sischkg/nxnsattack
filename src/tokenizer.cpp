#include "tokenizer.hpp"
#include <iostream>
#include <boost/shared_ptr.hpp>

#if 0

/* State Transition Table.

   initial state: token / not quoted
   delimiter: ' '+, '\t'+
   quote: '"'
   espcae: '\\'


   pre state                              | char       | post state                             | action
   ---------------------------------------|------------|----------------------------------------|---------------------
   token     / not quoted / not escaped   | token      | token     / not quoted / not escaped   | append char to token.
   token     / not quoted / not escaped   | delimiter  | delimiter / not quoted / not escaped   | terminate token
   token     / not quoted / not escaped   | quote      | token     / quoted     / not escaped   | none
   token     / not quoted / not escaped   | escape     | toekn     / not quoted / escpaed       | none

   delimiter / not quoted / not escaped   | token      | token     / not quoted / not escaped   | append char to new token
   delimiter / not quoted / not escaped   | delimiter  | delimiter / not quoted / not escaped   | none
   delimiter / not quoted / not escaped   | quote      | token     / quoted     / not escaped   | none
   delimiter / not quoted / not escaped   | espape     | delimiter / not quoted / escaped       | none

   token     /     quoted / not escaped   | token      | token     /     quoted / not escaped   | append char to token
   token     /     quoted / not escaped   | delimiter  | token     /     quoted / not escaped   | append cahr to token
   token     /     quoted / not escaped   | quote      | token     / not quoted / not escaped   | none
   token     /     quoted / not escaped   | espace     | token     /     quoted /     escaped   | none

   delimiter /     quoted / not escaped   | --------------------------------------------------------------------------

   token     / not quoted /     escaped   | token      | token     / not quoted / not escaped   | append char to token
   token     / not quoted /     escaped   | delimiter  | token     / not quoted / not escaped   | append char to token
   token     / not quoted /     escaped   | quote      | token     / not quoted / not escaped   | append char to token
   token     / not quoted /     escaped   | escpae     | token     / not quoted / not escaped   | append char to token

   delimiter / not quoted /     escaped   | --------------------------------------------------------------------------

   token     /     quoted /     escaped   | token      | token     /     quoted / not escaped   | append char to token
   token     /     quoted /     escaped   | delimiter  | token     /     quoted / not escaped   | append char to token
   token     /     quoted /     escaped   | quote      | token     /     quoted / not escaped   | append char to token
   token     /     quoted /     escaped   | espace     | token     /     quoted / not escaped   | append char to token

   delimiter /     quoted /     escaped   | -------------------------------------------------------------------------

*/

#endif

enum TokenState {
    TOKEN_STATE     = 0,
    DELIMITER_STATE = 1,
};

enum QuoteState {
    NOT_QUOTED_STATE = 0,
    QUOTED_STATE     = 1,
};

enum EscapeState {
    NOT_ESCAPED_STATE = 0,
    ESCAPED_STATE     = 1,
};

enum CharType {
    TOKEN,
    DELIMITER,
    QUOTE,
    ESCAPE,
};

static CharType getCharType( char c )
{
    if ( '\\' == c )
	return ESCAPE;
    if ( '"' == c )
	return QUOTE;
    if ( ' ' == c || '\t' == c )
	return DELIMITER;
    return TOKEN;
}


class Action
{
public:
    virtual ~Action()
    {}
    virtual void doChar( std::vector<std::string> &tokens,
			 std::string &tmp_token,
			 char c ) = 0;
};


class AppendChar : public Action
{
public:
    void doChar( std::vector<std::string> &tokens, std::string &tmp_token, char c )
    {
	tmp_token.push_back( c );
    }
};

class TerminateToken : public Action
{
public:
    void doChar( std::vector<std::string> &tokens, std::string &tmp_token, char c )
    {
	tokens.push_back( tmp_token );
	tmp_token.clear();
    }
};


class Transition
{
public:
    Transition( TokenState next_t  = TOKEN_STATE,
		QuoteState next_q  = NOT_QUOTED_STATE,
		EscapeState next_e = NOT_ESCAPED_STATE,
		boost::shared_ptr<Action> a = boost::shared_ptr<Action>() )
	: mNextTokenState( next_t ),
	  mNextQuoteState( next_q ),
	  mNextEscapeState( next_e ),
	  mAction( a )
    {}
    
    TokenState getNextTokenState() const   { return mNextTokenState; }
    QuoteState getNextQuoteState() const   { return mNextQuoteState; }
    EscapeState getNextEscapeState() const { return mNextEscapeState; }

    void doChar( std::vector<std::string> &tokens, std::string &tmp_token, char c ) const
    {
	if ( mAction )
	    mAction->doChar( tokens, tmp_token, c );
    }
    
private:
    TokenState mNextTokenState;
    QuoteState mNextQuoteState;
    EscapeState mNextEscapeState;
    boost::shared_ptr<Action> mAction;
};


static const Transition TRANSITION_TABLE[ESCAPED_STATE+1][QUOTED_STATE+1][DELIMITER_STATE+1][ESCAPE+1] = {
    {
	{
	    {
		Transition( TOKEN_STATE,     NOT_QUOTED_STATE, NOT_ESCAPED_STATE, boost::shared_ptr<Action>( new AppendChar ) ),
		Transition( DELIMITER_STATE, NOT_QUOTED_STATE, NOT_ESCAPED_STATE, boost::shared_ptr<Action>( new TerminateToken ) ),
		Transition( TOKEN_STATE,     QUOTED_STATE,     NOT_ESCAPED_STATE ),
		Transition( TOKEN_STATE,     NOT_QUOTED_STATE,     ESCAPED_STATE ),
	    },
	    {
		Transition( TOKEN_STATE,     NOT_QUOTED_STATE, NOT_ESCAPED_STATE, boost::shared_ptr<Action>( new AppendChar ) ),
		Transition( DELIMITER_STATE, NOT_QUOTED_STATE, NOT_ESCAPED_STATE ),
		Transition( TOKEN_STATE,         QUOTED_STATE, NOT_ESCAPED_STATE ),
		Transition( TOKEN_STATE,     NOT_QUOTED_STATE,     ESCAPED_STATE ),
	    },
	},
	{
	    {
		Transition( TOKEN_STATE,         QUOTED_STATE, NOT_ESCAPED_STATE, boost::shared_ptr<Action>( new AppendChar ) ),
		Transition( TOKEN_STATE,         QUOTED_STATE, NOT_ESCAPED_STATE, boost::shared_ptr<Action>( new AppendChar ) ),
		Transition( TOKEN_STATE,     NOT_QUOTED_STATE, NOT_ESCAPED_STATE ),
		Transition( TOKEN_STATE,     NOT_QUOTED_STATE,     ESCAPED_STATE ),
	    },
	    {
	    },
	},
    },
    {
	{
	    {
		Transition( TOKEN_STATE,     NOT_QUOTED_STATE, NOT_ESCAPED_STATE, boost::shared_ptr<Action>( new AppendChar ) ),
		Transition( TOKEN_STATE,     NOT_QUOTED_STATE, NOT_ESCAPED_STATE, boost::shared_ptr<Action>( new AppendChar ) ),
		Transition( TOKEN_STATE,     NOT_QUOTED_STATE, NOT_ESCAPED_STATE, boost::shared_ptr<Action>( new AppendChar ) ),
		Transition( TOKEN_STATE,     NOT_QUOTED_STATE, NOT_ESCAPED_STATE, boost::shared_ptr<Action>( new AppendChar ) ),
	    },
	    {
	    },
	},
	{
	    {
		Transition( TOKEN_STATE,         QUOTED_STATE, NOT_ESCAPED_STATE, boost::shared_ptr<Action>( new AppendChar ) ),
		Transition( TOKEN_STATE,         QUOTED_STATE, NOT_ESCAPED_STATE, boost::shared_ptr<Action>( new AppendChar ) ),
		Transition( TOKEN_STATE,         QUOTED_STATE, NOT_ESCAPED_STATE, boost::shared_ptr<Action>( new AppendChar ) ),
		Transition( TOKEN_STATE,         QUOTED_STATE, NOT_ESCAPED_STATE, boost::shared_ptr<Action>( new AppendChar ) ),
	    },
	    {
	    },
	},
    },
};


std::vector<std::string> tokenize( const std::string &line )
{
    std::vector<std::string> tokens;
    std::string tmp_token;

    TokenState  token_state  = TOKEN_STATE;
    QuoteState  quote_state  = NOT_QUOTED_STATE;
    EscapeState escape_state = NOT_ESCAPED_STATE;

    for ( char c : line ) {
	CharType char_type = getCharType( c );
	const Transition &transition = TRANSITION_TABLE[escape_state][quote_state][token_state][char_type];
	transition.doChar( tokens, tmp_token, c );

        token_state  = transition.getNextTokenState();
	quote_state  = transition.getNextQuoteState();
	escape_state = transition.getNextEscapeState();
    }
    if ( tmp_token != "" )
	tokens.push_back( tmp_token );

    return tokens;
}


