#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hexdump.h"
#include "pcap.h"
#include "pkx.h"
#include "protocols.h"

/*-- structs --------------------------------------------*/
struct packet_ninty_1 {
  uint8_t  src;
  uint8_t  dst;

  uint8_t  op;   /* Lower nibble: packet (chunk) type.  Upper nibble: bitfield? */
                 /*  #  sections   payload
                    -----------------------
                     0  0 1     4        0   handshake
                     1  0 1   3 4        ?  (sometimes has payload)  \
                     2      2           >0  (DATA packet)            | main
                     3                   0                           | comm.
                     4                   0  ping/pong?               / */
  uint8_t  un8;

  uint8_t  un1; /* split into nibbles? */

  uint32_t un2;
  uint16_t un3;
  uint32_t un4;
  uint8_t  un5;

  /* TODO */
} __attribute__((packed));

struct packet_ninty_2_section {
  uint8_t type;
  uint8_t length;
  uint8_t data[0];
} __attribute__((packed));

struct packet_ninty_2_header {
  uint16_t magic;
  uint8_t  un1;

  uint8_t  section_bitfield; /* (seemingly) maps somewhat to what sections are present. */
                             /* 0f  sections: 00 01    03 04     1111
                                0b  sections: 00 01       04     1011
                                03  sections:       02           0011
                                00  sections:                    0000 */

  uint16_t size; /* of payload, in octets */

  uint8_t  src;
  uint8_t  dst;

  uint8_t  op;   /* Lower nibble: packet (chunk) type.  Upper nibble: bitfield. */
                 /*  #  sections   payload
                    -----------------------
                     0  0 1     4        0   handshake
                     1  0 1   3 4        ?  (sometimes has payload)  \
                     2      2           >0  (DATA packet)            | main
                     3                   0                           | comm.
                     4                   0  ping/pong?               / */

  uint8_t  un8;

  uint8_t  from; /* conversation ID? sender ID? consistent for (sender,receiver) */
                 /* pair. optional?  00, CF, 7D, F4, D0, E8, D1 */

  uint8_t  flags1;
  uint16_t pack_id;

  uint8_t  checksumish[16];

  /* Repeated struct packet_ninty_2_section until terminator section */
  struct packet_ninty_2_section sections[0];

  /* uint8_t payload[size]; */

} __attribute__((packed));

struct packet_ninty_2_8e2 {
  uint16_t un1;
  uint16_t length;

//uint8_t  un2;
//uint8_t  un3;
//uint16_t un4;
  uint32_t un2;

  uint32_t un5; /* Note: actually a 4-byte struct */
  uint32_t un6;
  uint32_t un7;

  uint32_t un8;
  uint32_t sublength;

  /* `sublength` octets of data */
  uint8_t  data[0];
} __attribute__((packed));

void print_pokemon_string(uint16_t *str, int maxlen) {
  for (int i=0; i<maxlen && str[i] != 0; i++) {
    putchar(str[i]); /* TODO: proper charset lookup. */
  }
}

void dump_pokemon(struct pokemon *pkmn) {
	char stmt[500];

	char PokemonList[725][20] = { "-----", "Bulbasaur", "Ivysaur", "Venusaur", "Charmander", "Charmeleon", "Charizard", "Squirtle", "Wartortle", "Blastoise", "Caterpie", "Metapod", "Butterfree", "Weedle", "Kakuna", "Beedrill", "Pidgey", "Pidgeotto", "Pidgeot", "Rattata", "Raticate", "Spearow", "Fearow", "Ekans", "Arbok", "Pikachu", "Raichu", "Sandshrew", "Sandslash", "Nidoran⑮", "Nidorina", "Nidoqueen", "Nidoran⑭", "Nidorino", "Nidoking", "Clefairy", "Clefable", "Vulpix", "Ninetales", "Jigglypuff", "Wigglytuff", "Zubat", "Golbat", "Oddish", "Gloom", "Vileplume", "Paras", "Parasect", "Venonat", "Venomoth", "Diglett", "Dugtrio", "Meowth", "Persian", "Psyduck", "Golduck", "Mankey", "Primeape", "Growlithe", "Arcanine", "Poliwag", "Poliwhirl", "Poliwrath", "Abra", "Kadabra", "Alakazam", "Machop", "Machoke", "Machamp", "Bellsprout", "Weepinbell", "Victreebel", "Tentacool", "Tentacruel", "Geodude", "Graveler", "Golem", "Ponyta", "Rapidash", "Slowpoke", "Slowbro", "Magnemite", "Magneton", "Farfetch'd", "Doduo", "Dodrio", "Seel", "Dewgong", "Grimer", "Muk", "Shellder", "Cloyster", "Gastly", "Haunter", "Gengar", "Onix", "Drowzee", "Hypno", "Krabby", "Kingler", "Voltorb", "Electrode", "Exeggcute", "Exeggutor", "Cubone", "Marowak", "Hitmonlee", "Hitmonchan", "Lickitung", "Koffing", "Weezing", "Rhyhorn", "Rhydon", "Chansey", "Tangela", "Kangaskhan", "Horsea", "Seadra", "Goldeen", "Seaking", "Staryu", "Starmie", "Mr. Mime", "Scyther", "Jynx", "Electabuzz", "Magmar", "Pinsir", "Tauros", "Magikarp", "Gyarados", "Lapras", "Ditto", "Eevee", "Vaporeon", "Jolteon", "Flareon", "Porygon", "Omanyte", "Omastar", "Kabuto", "Kabutops", "Aerodactyl", "Snorlax", "Articuno", "Zapdos", "Moltres", "Dratini", "Dragonair", "Dragonite", "Mewtwo", "Mew", "Chikorita", "Bayleef", "Meganium", "Cyndaquil", "Quilava", "Typhlosion", "Totodile", "Croconaw", "Feraligatr", "Sentret", "Furret", "Hoothoot", "Noctowl", "Ledyba", "Ledian", "Spinarak", "Ariados", "Crobat", "Chinchou", "Lanturn", "Pichu", "Cleffa", "Igglybuff", "Togepi", "Togetic", "Natu", "Xatu", "Mareep", "Flaaffy", "Ampharos", "Bellossom", "Marill", "Azumarill", "Sudowoodo", "Politoed", "Hoppip", "Skiploom", "Jumpluff", "Aipom", "Sunkern", "Sunflora", "Yanma", "Wooper", "Quagsire", "Espeon", "Umbreon", "Murkrow", "Slowking", "Misdreavus", "Unown", "Wobbuffet", "Girafarig", "Pineco", "Forretress", "Dunsparce", "Gligar", "Steelix", "Snubbull", "Granbull", "Qwilfish", "Scizor", "Shuckle", "Heracross", "Sneasel", "Teddiursa", "Ursaring", "Slugma", "Magcargo", "Swinub", "Piloswine", "Corsola", "Remoraid", "Octillery", "Delibird", "Mantine", "Skarmory", "Houndour", "Houndoom", "Kingdra", "Phanpy", "Donphan", "Porygon2", "Stantler", "Smeargle", "Tyrogue", "Hitmontop", "Smoochum", "Elekid", "Magby", "Miltank", "Blissey", "Raikou", "Entei", "Suicune", "Larvitar", "Pupitar", "Tyranitar", "Lugia", "Ho-Oh", "Celebi", "Treecko", "Grovyle", "Sceptile", "Torchic", "Combusken", "Blaziken", "Mudkip", "Marshtomp", "Swampert", "Poochyena", "Mightyena", "Zigzagoon", "Linoone", "Wurmple", "Silcoon", "Beautifly", "Cascoon", "Dustox", "Lotad", "Lombre", "Ludicolo", "Seedot", "Nuzleaf", "Shiftry", "Taillow", "Swellow", "Wingull", "Pelipper", "Ralts", "Kirlia", "Gardevoir", "Surskit", "Masquerain", "Shroomish", "Breloom", "Slakoth", "Vigoroth", "Slaking", "Nincada", "Ninjask", "Shedinja", "Whismur", "Loudred", "Exploud", "Makuhita", "Hariyama", "Azurill", "Nosepass", "Skitty", "Delcatty", "Sableye", "Mawile", "Aron", "Lairon", "Aggron", "Meditite", "Medicham", "Electrike", "Manectric", "Plusle", "Minun", "Volbeat", "Illumise", "Roselia", "Gulpin", "Swalot", "Carvanha", "Sharpedo", "Wailmer", "Wailord", "Numel", "Camerupt", "Torkoal", "Spoink", "Grumpig", "Spinda", "Trapinch", "Vibrava", "Flygon", "Cacnea", "Cacturne", "Swablu", "Altaria", "Zangoose", "Seviper", "Lunatone", "Solrock", "Barboach", "Whiscash", "Corphish", "Crawdaunt", "Baltoy", "Claydol", "Lileep", "Cradily", "Anorith", "Armaldo", "Feebas", "Milotic", "Castform", "Kecleon", "Shuppet", "Banette", "Duskull", "Dusclops", "Tropius", "Chimecho", "Absol", "Wynaut", "Snorunt", "Glalie", "Spheal", "Sealeo", "Walrein", "Clamperl", "Huntail", "Gorebyss", "Relicanth", "Luvdisc", "Bagon", "Shelgon", "Salamence", "Beldum", "Metang", "Metagross", "Regirock", "Regice", "Registeel", "Latias", "Latios", "Kyogre", "Groudon", "Rayquaza", "Jirachi", "Deoxys", "Turtwig", "Grotle", "Torterra", "Chimchar", "Monferno", "Infernape", "Piplup", "Prinplup", "Empoleon", "Starly", "Staravia", "Staraptor", "Bidoof", "Bibarel", "Kricketot", "Kricketune", "Shinx", "Luxio", "Luxray", "Budew", "Roserade", "Cranidos", "Rampardos", "Shieldon", "Bastiodon", "Burmy", "Wormadam", "Mothim", "Combee", "Vespiquen", "Pachirisu", "Buizel", "Floatzel", "Cherubi", "Cherrim", "Shellos", "Gastrodon", "Ambipom", "Drifloon", "Drifblim", "Buneary", "Lopunny", "Mismagius", "Honchkrow", "Glameow", "Purugly", "Chingling", "Stunky", "Skuntank", "Bronzor", "Bronzong", "Bonsly", "Mime Jr.", "Happiny", "Chatot", "Spiritomb", "Gible", "Gabite", "Garchomp", "Munchlax", "Riolu", "Lucario", "Hippopotas", "Hippowdon", "Skorupi", "Drapion", "Croagunk", "Toxicroak", "Carnivine", "Finneon", "Lumineon", "Mantyke", "Snover", "Abomasnow", "Weavile", "Magnezone", "Lickilicky", "Rhyperior", "Tangrowth", "Electivire", "Magmortar", "Togekiss", "Yanmega", "Leafeon", "Glaceon", "Gliscor", "Mamoswine", "Porygon-Z", "Gallade", "Probopass", "Dusknoir", "Froslass", "Rotom", "Uxie", "Mesprit", "Azelf", "Dialga", "Palkia", "Heatran", "Regigigas", "Giratina", "Cresselia", "Phione", "Manaphy", "Darkrai", "Shaymin", "Arceus", "Victini", "Snivy", "Servine", "Serperior", "Tepig", "Pignite", "Emboar", "Oshawott", "Dewott", "Samurott", "Patrat", "Watchog", "Lillipup", "Herdier", "Stoutland", "Purrloin", "Liepard", "Pansage", "Simisage", "Pansear", "Simisear", "Panpour", "Simipour", "Munna", "Musharna", "Pidove", "Tranquill", "Unfezant", "Blitzle", "Zebstrika", "Roggenrola", "Boldore", "Gigalith", "Woobat", "Swoobat", "Drilbur", "Excadrill", "Audino", "Timburr", "Gurdurr", "Conkeldurr", "Tympole", "Palpitoad", "Seismitoad", "Throh", "Sawk", "Sewaddle", "Swadloon", "Leavanny", "Venipede", "Whirlipede", "Scolipede", "Cottonee", "Whimsicott", "Petilil", "Lilligant", "Basculin", "Sandile", "Krokorok", "Krookodile", "Darumaka", "Darmanitan", "Maractus", "Dwebble", "Crustle", "Scraggy", "Scrafty", "Sigilyph", "Yamask", "Cofagrigus", "Tirtouga", "Carracosta", "Archen", "Archeops", "Trubbish", "Garbodor", "Zorua", "Zoroark", "Minccino", "Cinccino", "Gothita", "Gothorita", "Gothitelle", "Solosis", "Duosion", "Reuniclus", "Ducklett", "Swanna", "Vanillite", "Vanillish", "Vanilluxe", "Deerling", "Sawsbuck", "Emolga", "Karrablast", "Escavalier", "Foongus", "Amoonguss", "Frillish", "Jellicent", "Alomomola", "Joltik", "Galvantula", "Ferroseed", "Ferrothorn", "Klink", "Klang", "Klinklang", "Tynamo", "Eelektrik", "Eelektross", "Elgyem", "Beheeyem", "Litwick", "Lampent", "Chandelure", "Axew", "Fraxure", "Haxorus", "Cubchoo", "Beartic", "Cryogonal", "Shelmet", "Accelgor", "Stunfisk", "Mienfoo", "Mienshao", "Druddigon", "Golett", "Golurk", "Pawniard", "Bisharp", "Bouffalant", "Rufflet", "Braviary", "Vullaby", "Mandibuzz", "Heatmor", "Durant", "Deino", "Zweilous", "Hydreigon", "Larvesta", "Volcarona", "Cobalion", "Terrakion", "Virizion", "Tornadus", "Thundurus", "Reshiram", "Zekrom", "Landorus", "Kyurem", "Keldeo", "Meloetta", "Genesect", "Chespin", "Quilladin", "Chesnaught", "Fennekin", "Braixen", "Delphox", "Froakie", "Frogadier", "Greninja", "Bunnelby", "Diggersby", "Fletchling", "Fletchinder", "Talonflame", "Scatterbug", "Spewpa", "Vivillon", "Litleo", "Pyroar", "Flabébé", "Floette", "Florges", "Skiddo", "Gogoat", "Pancham", "Pangoro", "Furfrou", "Espurr", "Meowstic", "Honedge", "Doublade", "Aegislash", "Spritzee", "Aromatisse", "Swirlix", "Slurpuff", "Inkay", "Malamar", "Binacle", "Barbaracle", "Skrelp", "Dragalge", "Clauncher", "Clawitzer", "Helioptile", "Heliolisk", "Tyrunt", "Tyrantrum", "Amaura", "Aurorus", "Sylveon", "Hawlucha", "Dedenne", "Carbink", "Goomy", "Sliggoo", "Goodra", "Klefki", "Phantump", "Trevenant", "Pumpkaboo", "Gourgeist", "Bergmite", "Avalugg", "Noibat", "Noivern", "Xerneas", "Yveltal", "Zygarde", "Diancie", "Volcanion", "Hoopa" };
	char MoveList[620][20] = { "(none)", "Pound", "Karate Chop", "Double Slap", "Comet Punch", "Mega Punch", "Pay Day", "Fire Punch", "Ice Punch", "Thunder Punch", "Scratch", "ViceGrip", "Guillotine", "Razor Wind", "Swords Dance", "Cut", "Gust", "Wing Attack", "Whirlwind", "Fly", "Bind", "Slam", "Vine Whip", "Stomp", "Double Kick", "Mega Kick", "Jump Kick", "Rolling Kick", "Sand-Attack", "Headbutt", "Horn Attack", "Fury Attack", "Horn Drill", "Tackle", "Body Slam", "Wrap", "Take Down", "Thrash", "Double-Edge", "Tail Whip", "Poison Sting", "Twineedle", "Pin Missile", "Leer", "Bite", "Growl", "Roar", "Sing", "Supersonic", "SonicBoom", "Disable", "Acid", "Ember", "Flamethrower", "Mist", "Water Gun", "Hydro Pump", "Surf", "Ice Beam", "Blizzard", "Psybeam", "BubbleBeam", "Aurora Beam", "Hyper Beam", "Peck", "Drill Peck", "Submission", "Low Kick", "Counter", "Seismic Toss", "Strength", "Absorb", "Mega Drain", "Leech Seed", "Growth", "Razor Leaf", "SolarBeam", "PoisonPowder", "Stun Spore", "Sleep Powder", "Petal Dance", "String Shot", "Dragon Rage", "Fire Spin", "ThunderShock", "Thunderbolt", "Thunder Wave", "Thunder", "Rock Throw", "Earthquake", "Fissure", "Dig", "Toxic", "Confusion", "Psychic", "Hypnosis", "Meditate", "Agility", "Quick Attack", "Rage", "Teleport", "Night Shade", "Mimic", "Screech", "Double Team", "Recover", "Harden", "Minimize", "SmokeScreen", "Confuse Ray", "Withdraw", "Defense Curl", "Barrier", "Light Screen", "Haze", "Reflect", "Focus Energy", "Bide", "Metronome", "Mirror Move", "Selfdestruct", "Egg Bomb", "Lick", "Smog", "Sludge", "Bone Club", "Fire Blast", "Waterfall", "Clamp", "Swift", "Skull Bash", "Spike Cannon", "Constrict", "Amnesia", "Kinesis", "Softboiled", "Hi Jump Kick", "Glare", "Dream Eater", "Poison Gas", "Barrage", "Leech Life", "Lovely Kiss", "Sky Attack", "Transform", "Bubble", "Dizzy Punch", "Spore", "Flash", "Psywave", "Splash", "Acid Armor", "Crabhammer", "Explosion", "Fury Swipes", "Bonemerang", "Rest", "Rock Slide", "Hyper Fang", "Sharpen", "Conversion", "Tri Attack", "Super Fang", "Slash", "Substitute", "Struggle", "Sketch", "Triple Kick", "Thief", "Spider Web", "Mind Reader", "Nightmare", "Flame Wheel", "Snore", "Curse", "Flail", "Conversion 2", "Aeroblast", "Cotton Spore", "Reversal", "Spite", "Powder Snow", "Protect", "Mach Punch", "Scary Face", "Faint Attack", "Sweet Kiss", "Belly Drum", "Sludge Bomb", "Mud-Slap", "Octazooka", "Spikes", "Zap Cannon", "Foresight", "Destiny Bond", "Perish Song", "Icy Wind", "Detect", "Bone Rush", "Lock-On", "Outrage", "Sandstorm", "Giga Drain", "Endure", "Charm", "Rollout", "False Swipe", "Swagger", "Milk Drink", "Spark", "Fury Cutter", "Steel Wing", "Mean Look", "Attract", "Sleep Talk", "Heal Bell", "Return", "Present", "Frustration", "Safeguard", "Pain Split", "Sacred Fire", "Magnitude", "DynamicPunch", "Megahorn", "DragonBreath", "Baton Pass", "Encore", "Pursuit", "Rapid Spin", "Sweet Scent", "Iron Tail", "Metal Claw", "Vital Throw", "Morning Sun", "Synthesis", "Moonlight", "Hidden Power", "Cross Chop", "Twister", "Rain Dance", "Sunny Day", "Crunch", "Mirror Coat", "Psych Up", "ExtremeSpeed", "AncientPower", "Shadow Ball", "Future Sight", "Rock Smash", "Whirlpool", "Beat Up", "Fake Out", "Uproar", "Stockpile", "Spit Up", "Swallow", "Heat Wave", "Hail", "Torment", "Flatter", "Will-O-Wisp", "Memento", "Facade", "Focus Punch", "SmellingSalt", "Follow Me", "Nature Power", "Charge", "Taunt", "Helping Hand", "Trick", "Role Play", "Wish", "Assist", "Ingrain", "Superpower", "Magic Coat", "Recycle", "Revenge", "Brick Break", "Yawn", "Knock Off", "Endeavor", "Eruption", "Skill Swap", "Imprison", "Refresh", "Grudge", "Snatch", "Secret Power", "Dive", "Arm Thrust", "Camouflage", "Tail Glow", "Luster Purge", "Mist Ball", "FeatherDance", "Teeter Dance", "Blaze Kick", "Mud Sport", "Ice Ball", "Needle Arm", "Slack Off", "Hyper Voice", "Poison Fang", "Crush Claw", "Blast Burn", "Hydro Cannon", "Meteor Mash", "Astonish", "Weather Ball", "Aromatherapy", "Fake Tears", "Air Cutter", "Overheat", "Odor Sleuth", "Rock Tomb", "Silver Wind", "Metal Sound", "GrassWhistle", "Tickle", "Cosmic Power", "Water Spout", "Signal Beam", "Shadow Punch", "Extrasensory", "Sky Uppercut", "Sand Tomb", "Sheer Cold", "Muddy Water", "Bullet Seed", "Aerial Ace", "Icicle Spear", "Iron Defense", "Block", "Howl", "Dragon Claw", "Frenzy Plant", "Bulk Up", "Bounce", "Mud Shot", "Poison Tail", "Covet", "Volt Tackle", "Magical Leaf", "Water Sport", "Calm Mind", "Leaf Blade", "Dragon Dance", "Rock Blast", "Shock Wave", "Water Pulse", "Doom Desire", "Psycho Boost", "Roost", "Gravity", "Miracle Eye", "Wake-Up Slap", "Hammer Arm", "Gyro Ball", "Healing Wish", "Brine", "Natural Gift", "Feint", "Pluck", "Tailwind", "Acupressure", "Metal Burst", "U-turn", "Close Combat", "Payback", "Assurance", "Embargo", "Fling", "Psycho Shift", "Trump Card", "Heal Block", "Wring Out", "Power Trick", "Gastro Acid", "Lucky Chant", "Me First", "Copycat", "Power Swap", "Guard Swap", "Punishment", "Last Resort", "Worry Seed", "Sucker Punch", "Toxic Spikes", "Heart Swap", "Aqua Ring", "Magnet Rise", "Flare Blitz", "Force Palm", "Aura Sphere", "Rock Polish", "Poison Jab", "Dark Pulse", "Night Slash", "Aqua Tail", "Seed Bomb", "Air Slash", "X-Scissor", "Bug Buzz", "Dragon Pulse", "Dragon Rush", "Power Gem", "Drain Punch", "Vacuum Wave", "Focus Blast", "Energy Ball", "Brave Bird", "Earth Power", "Switcheroo", "Giga Impact", "Nasty Plot", "Bullet Punch", "Avalanche", "Ice Shard", "Shadow Claw", "Thunder Fang", "Ice Fang", "Fire Fang", "Shadow Sneak", "Mud Bomb", "Psycho Cut", "Zen Headbutt", "Mirror Shot", "Flash Cannon", "Rock Climb", "Defog", "Trick Room", "Draco Meteor", "Discharge", "Lava Plume", "Leaf Storm", "Power Whip", "Rock Wrecker", "Cross Poison", "Gunk Shot", "Iron Head", "Magnet Bomb", "Stone Edge", "Captivate", "Stealth Rock", "Grass Knot", "Chatter", "Judgment", "Bug Bite", "Charge Beam", "Wood Hammer", "Aqua Jet", "Attack Order", "Defend Order", "Heal Order", "Head Smash", "Double Hit", "Roar of Time", "Spacial Rend", "Lunar Dance", "Crush Grip", "Magma Storm", "Dark Void", "Seed Flare", "Ominous Wind", "Shadow Force", "Hone Claws", "Wide Guard", "Guard Split", "Power Split", "Wonder Room", "Psyshock", "Venoshock", "Autotomize", "Rage Powder", "Telekinesis", "Magic Room", "Smack Down", "Storm Throw", "Flame Burst", "Sludge Wave", "Quiver Dance", "Heavy Slam", "Synchronoise", "Electro Ball", "Soak", "Flame Charge", "Coil", "Low Sweep", "Acid Spray", "Foul Play", "Simple Beam", "Entrainment", "After You", "Round", "Echoed Voice", "Chip Away", "Clear Smog", "Stored Power", "Quick Guard", "Ally Switch", "Scald", "Shell Smash", "Heal Pulse", "Hex", "Sky Drop", "Shift Gear", "Circle Throw", "Incinerate", "Quash", "Acrobatics", "Reflect Type", "Retaliate", "Final Gambit", "Bestow", "Inferno", "Water Pledge", "Fire Pledge", "Grass Pledge", "Volt Switch", "Struggle Bug", "Bulldoze", "Frost Breath", "Dragon Tail", "Work Up", "Electroweb", "Wild Charge", "Drill Run", "Dual Chop", "Heart Stamp", "Horn Leech", "Sacred Sword", "Razor Shell", "Heat Crash", "Leaf Tornado", "Steamroller", "Cotton Guard", "Night Daze", "Psystrike", "Tail Slap", "Hurricane", "Head Charge", "Gear Grind", "Searing Shot", "Techno Blast", "Relic Song", "Secret Sword", "Glaciate", "Bolt Strike", "Blue Flare", "Fiery Dance", "Freeze Shock", "Ice Burn", "Snarl", "Icicle Crash", "V-create", "Fusion Flare", "Fusion Bolt", "Flying Press", "Mat Block", "Belch", "Rototiller", "Sticky Web", "Fell Stinger", "Phantom Force", "Trick-or-Treat", "Noble Roar", "Ion Deluge", "Parabolic Charge", "Forest's Curse", "Petal Blizzard", "Freeze-Dry", "Disarming Voice", "Parting Shot", "Topsy-Turvy", "Draining Kiss", "Crafty Shield", "Flower Shield", "Grassy Terrain", "Misty Terrain", "Electrify", "Play Rough", "Fairy Wind", "Moonblast", "Boomburst", "Fairy Lock", "King's Shield", "Play Nice", "Confide", "Move 591", "Move 592", "Move 593", "Water Shuriken", "Mystical Fire", "Spiky Shield", "Aromatic Mist", "Eerie Impulse", "Venom Drench", "Powder", "Geomancy", "Magnetic Flux", "Move 603", "Electric Terrain", "Dazzling Gleam", "Move 606", "Move 607", "Baby-Doll Eyes", "Nuzzle", "Move 610", "Infestation", "Power-Up Punch", "Oblivion Wing", "Move 614", "Move 615", "Land's Wrath" };
	char AbilityList[200][20] = { "(none)", "Stench", "Drizzle", "Speed Boost", "Battle Armor", "Sturdy", "Damp", "Limber", "Sand Veil", "Static", "Volt Absorb", "Water Absorb", "Oblivous", "Cloud Nine", "CompoundEyes", "Insomnia", "Color Change", "Immunity", "Flash Fire", "Shield Dust", "Own Tempo", "Suction Cups", "Intimidate", "Shadow Tag", "Rough Skin", "Wonder Guard", "Levitate", "Effect Spore", "Synchronize", "Clear Body", "Natural Cure", "Lightningrod", "Serene Grace", "Swift Swim", "Chlorophyll", "Illuminate", "Trace", "Huge Power", "Poison Point", "Inner Focus", "Magma Armor", "Water Veil", "Magnet Pull", "Sound Proof", "Rain Dish", "Sand Stream", "Pressure", "Thick Fat", "Early Bird", "Flame Body", "Run Away", "Keen Eye", "Hyper Cutter", "Pickup", "Truant", "Hustle", "Cute Charm", "Plus", "Minus", "Forecasst", "Sticky Hold", "Shed Skin", "Guts", "Marvel Scale", "Liquid Ooze", "Overgrow", "Blaze", "Torrent", "Swarm", "Rock Head", "Drought", "Arena Trap", "Vital Spirit", "White Smoke", "Pure Power", "Shell Armor", "Air Lock", "Tangled Feet", "Motor Drive", "Rivalry", "Steadfast", "Snow Cloak", "Gluttony", "Anger Point", "Unburden", "Heatproof", "Simple", "Dry Skin", "Download", "Iron Fist", "Poison Heal", "Adaptability", "Skill Link", "Hydration", "Solar Power", "Quick Feet", "Normalize", "Sniper", "Magic Guard", "No Guard", "Stall", "Technician", "Leaf Guard", "Klutz", "Mold Breaker", "Super Luck", "Aftermath", "Anticipation", "Forewarn", "Unaware", "Tinted Lens", "Filter", "Slow Start", "Scrappy", "Storm Drain", "Ice Body", "Solid Rock", "Snow Warning", "Honey Gather", "Frisk", "Reckless", "Multitype", "Flower Gift", "Bad Dreams", "Pickpocket", "Sheer Force", "Contrary", "Unnerve", "Defiant", "Defeatist", "Cursed Body", "Healer", "Friend Guard", "Weak Armor", "Heavy Metal", "Light Metal", "Multiscale", "Toxic Boost", "Flame Boost", "Harvest", "Telepathy", "Moody", "Overcoat", "Poison Touch", "Regenerator", "Big Pecks", "Sand Rush", "Wonder Skin", "Analytic", "Illusion", "Imposter", "Infiltrator", "Mummy", "Moxie", "Justified", "Rattled", "Magic Bounce", "Sap Sipper", "Prankster", "Sand Force", "Iron Barbs", "Zen Mode", "Victory Star", "Turboblaze", "Teravolt", "Aroma Veil", "Flower Veil", "Cheek Pouch", "Protean", "Fur Coat", "Magician", "Bulletproof", "Competitive", "Strong Jaw", "Refrigerate", "Sweet Veil", "Stance Change", "Gale Wings", "Mega Launcher", "Grass Pelt", "Symbiosis", "Tough Claws", "Pixilate", "Gooey", "Ability 184", "Ability 185", "Dark Aura", "Fairy Aura", "Aura Break" };
	char ItemList[720][20] = { "(none)", "Master Ball", "Ultra Ball", "Great Ball", "Poké Ball", "Safari Ball", "Net Ball", "Dive Ball", "Nest Ball", "Repeat Ball", "Timer Ball", "Luxury Ball", "Premier Ball", "Dusk Ball", "Heal Ball", "Quick Ball", "Cherish Ball", "Potion", "Antidote", "Burn Heal", "Ice Heal", "Awakening", "Parlyz Heal", "Full Restore", "Max Potion", "Hyper Potion", "Super Potion", "Full Heal", "Revive", "Max Revive", "Fresh Water", "Soda Pop", "Lemonade", "Moomoo Milk", "EnergyPowder", "Energy Root", "Heal Powder", "Revival Herb", "Ether", "Max Ether", "Elixir", "Max Elixir", "Lava Cookie", "Berry Juice", "Sacred Ash", "HP Up", "Protein", "Iron", "Carbos", "Calcium", "Rare Candy", "PP Up", "Zinc", "PP Max", "Old Gateau", "Guard Spec.", "Dire Hit", "X Attack", "X Defend", "X Speed", "X Accuracy", "X Special", "X Sp. Def", "Poké Doll", "Fluffy Tail", "Blue Flute", "Yellow Flute", "Red Flute", "Black Flute", "White Flute", "Shoal Salt", "Shoal Shell", "Red Shard", "Blue Shard", "Yellow Shard", "Green Shard", "Super Repel", "Max Repel", "Escape Rope", "Repel", "Sun Stone", "Moon Stone", "Fire Stone", "Thunder Stone", "Water Stone", "Leaf Stone", "TinyMushroom", "Big Mushroom", "Pearl", "Big Pearl", "Stardust", "Star Piece", "Nugget", "Heart Scale", "Honey", "Growth Mulch", "Damp Mulch", "Stable Mulch", "Gooey Mulch", "Root Fossil", "Claw Fossil", "Helix Fossil", "Dome Fossil", "Old Amber", "Armor Fossil", "Skull Fossil", "Rare Bone", "Shiny Stone", "Dusk Stone", "Dawn Stone", "Oval Stone", "Odd Keystone", "Griseous Orb", " unknown", " unknown", " unknown", "Douse Drive", "Shock Drive", "Burn Drive", "Chill Drive", " unknown", " unknown", " unknown", " unknown", " unknown", " unknown", " unknown", " unknown", " unknown", " unknown", " unknown", " unknown", " unknown", " unknown", "Sweet Heart", "Adamant Orb", "Lustrous Orb", "Greet Mail", "Favored Mail", "RSVP Mail", "Thanks Mail", "Inquiry Mail", "Like Mail", "Reply Mail", "BridgeMail S", "BridgeMail D", "BridgeMail T", "BridgeMail V", "BridgeMail M", "Cheri Berry", "Chesto Berry", "Pecha Berry", "Rawst Berry", "Aspear Berry", "Leppa Berry", "Oran Berry", "Persim Berry", "Lum Berry", "Sitrus Berry", "Figy Berry", "Wiki Berry", "Mago Berry", "Aguav Berry", "Iapapa Berry", "Razz Berry", "Bluk Berry", "Nanab Berry", "Wepear Berry", "Pinap Berry", "Pomeg Berry", "Kelpsy Berry", "Qualot Berry", "Hondew Berry", "Grepa Berry", "Tamato Berry", "Cornn Berry", "Magost Berry", "Rabuta Berry", "Nomel Berry", "Spelon Berry", "Pamtre Berry", "Watmel Berry", "Durin Berry", "Belue Berry", "Occa Berry", "Passho Berry", "Wacan Berry", "Rindo Berry", "Yache Berry", "Chople Berry", "Kebia Berry", "Shuca Berry", "Coba Berry", "Payapa Berry", "Tanga Berry", "Charti Berry", "Kasib Berry", "Haban Berry", "Colbur Berry", "Babiri Berry", "Chilan Berry", "Liechi Berry", "Ganlon Berry", "Salac Berry", "Petaya Berry", "Apicot Berry", "Lansat Berry", "Starf Berry", "Enigma Berry", "Micle Berry", "Custap Berry", "Jaboca Berry", "Rowap Berry", "BrightPowder", "White Herb", "Macho Brace", "Exp. Share", "Quick Claw", "Soothe Bell", "Mental Herb", "Choice Band", "King's Rock", "SilverPowder", "Amulet Coin", "Cleanse Tag", "Soul Dew", "DeepSeaTooth", "DeepSeaScale", "Smoke Ball", "Everstone", "Focus Band", "Lucky Egg", "Scope Lens", "Metal Coat", "Leftovers", "Dragon Scale", "Light Ball", "Soft Sand", "Hard Stone", "Miracle Seed", "BlackGlasses", "Black Belt", "Magnet", "Mystic Water", "Sharp Beak", "Poison Barb", "NeverMeltIce", "Spell Tag", "TwistedSpoon", "Charcoal", "Dragon Fang", "Silk Scarf", "Up-Grade", "Shell Bell", "Sea Incense", "Lax Incense", "Lucky Punch", "Metal Powder", "Thick Club", "Stick", "Red Scarf", "Blue Scarf", "Pink Scarf", "Green Scarf", "Yellow Scarf", "Wide Lens", "Muscle Band", "Wise Glasses", "Expert Belt", "Light Clay", "Life Orb", "Power Herb", "Toxic Orb", "Flame Orb", "Quick Powder", "Focus Sash", "Zoom Lens", "Metronome", "Iron Ball", "Lagging Tail", "Destiny Knot", "Black Sludge", "Icy Rock", "Smooth Rock", "Heat Rock", "Damp Rock", "Grip Claw", "Choice Scarf", "Sticky Barb", "Power Bracer", "Power Belt", "Power Lens", "Power Band", "Power Anklet", "Power Weight", "Shed Shell", "Big Root", "Choice Specs", "Flame Plate", "Splash Plate", "Zap Plate", "Meadow Plate", "Icicle Plate", "Fist Plate", "Toxic Plate", "Earth Plate", "Sky Plate", "Mind Plate", "Insect Plate", "Stone Plate", "Spooky Plate", "Draco Plate", "Dread Plate", "Iron Plate", "Odd Incense", "Rock Incense", "Full Incense", "Wave Incense", "Rose Incense", "Luck Incense", "Pure Incense", "Protector", "Electirizer", "Magmarizer", "Dubious Disc", "Reaper Cloth", "Razor Claw", "Razor Fang", "TM01", "TM02", "TM03", "TM04", "TM05", "TM06", "TM07", "TM08", "TM09", "TM10", "TM11", "TM12", "TM13", "TM14", "TM15", "TM16", "TM17", "TM18", "TM19", "TM20", "TM21", "TM22", "TM23", "TM24", "TM25", "TM26", "TM27", "TM28", "TM29", "TM30", "TM31", "TM32", "TM33", "TM34", "TM35", "TM36", "TM37", "TM38", "TM39", "TM40", "TM41", "TM42", "TM43", "TM44", "TM45", "TM46", "TM47", "TM48", "TM49", "TM50", "TM51", "TM52", "TM53", "TM54", "TM55", "TM56", "TM57", "TM58", "TM59", "TM60", "TM61", "TM62", "TM63", "TM64", "TM65", "TM66", "TM67", "TM68", "TM69", "TM70", "TM71", "TM72", "TM73", "TM74", "TM75", "TM76", "TM77", "TM78", "TM79", "TM80", "TM81", "TM82", "TM83", "TM84", "TM85", "TM86", "TM87", "TM88", "TM89", "TM90", "TM91", "TM92", "HM01", "HM02", "HM03", "HM04", "HM05", "HM06", " unknown", " unknown", "Explorer Kit", "Loot Sack", "Rule Book", "Poké Radar", "Point Card", "Journal", "Seal Case", "Fashion Case", "Seal Bag", "Pal Pad", "Works Key", "Old Charm", "Galactic Key", "Red Chain", "Town Map", "Vs. Seeker", "Coin Case", "Old Rod", "Good Rod", "Super Rod", "Sprayduck", "Poffin Case", "Bicycle", "Suite Key", "Oak's Letter", "Lunar Wing", "Member Card", "Azure Flute", "S.S. Ticket", "Contest Pass", "Magma Stone", "Parcel", "Coupon 1", "Coupon 2", "Coupon 3", "Storage Key", "SecretPotion", "Vs. Recorder", "Gracidea", "Secret Key", "Apricorn Box", "Unown Report", "Berry Pots", "Dowsing MCHN", "Blue Card", "SlowpokeTail", "Clear Bell", "Card Key", "Basement Key", "SquirtBottle", "Red Scale", "Lost Item", "Pass", "Machine Part", "Silver Wing", "Rainbow Wing", "Mystery Egg", "Red Apricorn", "Ylw Apricorn", "Blu Apricorn", "Grn Apricorn", "Pnk Apricorn", "Wht Apricorn", "Blk Apricorn", "Fast Ball", "Level Ball", "Lure Ball", "Heavy Ball", "Love Ball", "Friend Ball", "Moon Ball", "Sport Ball", "Park Ball", "Photo Album", "GB Sounds", "Tidal Bell", "RageCandyBar", "Data Card 01", "Data Card 02", "Data Card 03", "Data Card 04", "Data Card 05", "Data Card 06", "Data Card 07", "Data Card 08", "Data Card 09", "Data Card 10", "Data Card 11", "Data Card 12", "Data Card 13", "Data Card 14", "Data Card 15", "Data Card 16", "Data Card 17", "Data Card 18", "Data Card 19", "Data Card 20", "Data Card 21", "Data Card 22", "Data Card 23", "Data Card 24", "Data Card 25", "Data Card 26", "Data Card 27", "Jade Orb", "Lock Capsule", "Red Orb", "Blue Orb", "Enigma Stone", "Prism Scale", "Eviolite", "Float Stone", "Rocky Helmet", "Air Balloon", "Red Card", "Ring Target", "Binding Band", "Absorb Bulb", "Cell Battery", "Eject Button", "Fire Gem", "Water Gem", "Electric Gem", "Grass Gem", "Ice Gem", "Fighting Gem", "Poison Gem", "Ground Gem", "Flying Gem", "Psychic Gem", "Bug Gem", "Rock Gem", "Ghost Gem", "Dragon Gem", "Dark Gem", "Steel Gem", "Normal Gem", "Health Wing", "Muscle Wing", "Resist Wing", "Genius Wing", "Clever Wing", "Swift Wing", "Pretty Wing", "Cover Fossil", "Plume Fossil", "Liberty Pass", "Pass Orb", "Dream Ball", "Poké Toy", "Prop Case", "Dragon Skull", "BalmMushroom", "Big Nugget", "Pearl String", "Comet Shard", "Relic Copper", "Relic Silver", "Relic Gold", "Relic Vase", "Relic Band", "Relic Statue", "Relic Crown", "Casteliacone", "Dire Hit 2", "X Speed 2", "X Special 2", "X Sp. Def 2", "X Defend 2", "X Attack 2", "X Accuracy 2", "X Speed 3", "X Special 3", "X Sp. Def 3", "X Defend 3", "X Attack 3", "X Accuracy 3", "X Speed 6", "X Special 6", "X Sp. Def 6", "X Defend 6", "X Attack 6", "X Accuracy 6", "Ability Urge", "Item Drop", "Item Urge", "Reset Urge", "Dire Hit 3", "Light Stone", "Dark Stone", "TM93", "TM94", "TM95", "Xtransceiver", "God Stone", "Gram 1", "Gram 2", "Gram 3", "Xtransceiver", "Medal Box", "DNA Splicers", "DNA Splicers", "Permit", "Oval Charm", "Shiny Charm", "Plasma Card", "Grubby Hanky", "Colress MCHN", "Dropped Item", "Dropped Item", "Reveal Glass", "Weakness Policy", "Assault Vest", "Item 641", "Item 642", "Item 643", "Pixie Plate", "Ability Capsule", "Whipped Dream", "Sachet", "Luminous Moss", "Snowball", "Safety Goggles", "Item 651", "Rich Mulch", "Surprise Mulch", "Boost Mulch", "Amaze Mulch", "Gengarite", "Gardevoirite", "Ampharosite", "Venusaurite", "Charizardite X", "Blastoisinite", "Mewtwonite X", "Mewtwonite Y", "Blazikenite", "Medichamite", "Houndoominite", "Aggronite", "Banettite", "Tyranitarite", "Scizorite", "Pinsirite", "Aerodactylite", "Lucarionite", "Abomasite", "Kangashkanite", "Gyaradosite", "Absolite", "Charizardite Y", "Alakazite", "Heracronite", "Mawilite", "Manectite", "Garchompite", "Item 684", "Item 685", "Roseli Berry", "Kee Berry", "Maranga Berry", "Item 689", "Item 690", "Item 691", "Item 692", "Item 693", "Item 694", "Item 695", "Item 696", "Item 697", "Item 698", "Bargain Ticket", "Item 700", "Item 701", "Item 702", "Item 703", "Strange Souvenir", "Item 705", "Item 706", "Item 707", "Lumiose Galette", "Item 709", "Jaw Fossil", "Sail Fossil", "Item 712", "Item 713", "Item 714", "Fairy Gem" };
	char NatureList[25][20] = { "Hardy", "Lonely", "Brave", "Adamant", "Naughty", "Bold", "Docile", "Relaxed", "Impish", "Lax", "Timid", "Hasty", "Serious", "Jolly", "Naive", "Modest", "Mild", "Quiet", "Bashful", "Rash", "Calm", "Gentle", "Sassy", "Careful", "Quirky" };

	sprintf(stmt," [%s%s%s] ", PokemonList[pkmn->a.id],
		((pkmn->b.iv_flags >> 30)?" Egg":""),
		((pkmn->a.flags >> 2 & 1) == 1)?"  ":
			(pkmn->a.flags >> 1 & 1) == 1?" F":" M" );
	sprintf(stmt + strlen(stmt)," TrainerID: %5d - SecretID: %5d - TSV: %4d |",
		pkmn->a.ot, pkmn->a.ot_secret, bitXor(pkmn->a.ot,pkmn->a.ot_secret) >> 4);
	sprintf(stmt + strlen(stmt)," PID: %08x - PSV: %4d\n",
		pkmn->a.pid, bitXor(pkmn->a.pid >> 16, (pkmn->a.pid << 16) >> 16) >> 4);
	sprintf(stmt + strlen(stmt)," Nature: %s, Ability: %s, ",
		NatureList[pkmn->a.nature],AbilityList[pkmn->a.ability]);
	sprintf(stmt + strlen(stmt), " IV: %2d/%2d/%2d/%2d/%2d/%2d",
		(pkmn->b.iv_flags >>  0) & 0x1F,
		(pkmn->b.iv_flags >>  5) & 0x1F,
		(pkmn->b.iv_flags >> 10) & 0x1F,
		(pkmn->b.iv_flags >> 20) & 0x1F,
		(pkmn->b.iv_flags >> 25) & 0x1F,
		(pkmn->b.iv_flags >> 15) & 0x1F);

	printf("\n-- Pokemon Info --\n%s\n",stmt);
  /*printf("enc_key: %04x  checksum: %02x\n",
         pkmn->enc_key, pkmn->checksum);*/

  /* A block */
  /*printf("\nA:\n");
  printf("  [%3d] {held: %2d} (OT: %04x (%04x))\n",
         pkmn->a.id, pkmn->a.held, pkmn->a.ot, pkmn->a.ot_secret);
  printf("  exp: %8d   ability: %02x %02x\n",
         pkmn->a.exp, pkmn->a.ability, pkmn->a.ability_no);
  printf("  nature: %d  flags: %02x\n",
         pkmn->a.nature, pkmn->a.flags);
  printf("  EV: %3d/%3d/%3d/%3d/%3d/%3d\n",
          pkmn->a.ev.hp,  pkmn->a.ev.atk, pkmn->a.ev.def,
          pkmn->a.ev.spa, pkmn->a.ev.spd, pkmn->a.ev.spe);
  printf("  rus? %02x   ribbons: %08x\n",
         pkmn->a.pokerus, pkmn->a.ribbons);*/

  /* B Block */
  /*printf("\nB:\n");
  printf("  nickname: '");
  print_pokemon_string(pkmn->b.nickname, 12);
  printf("'\n");

  printf("  moves:     %04x %04x %04x %04x\n",
         pkmn->b.moves[0], pkmn->b.moves[1], pkmn->b.moves[2], pkmn->b.moves[3]);
  printf("  pp:        %4d %4d %4d %4d\n",
         pkmn->b.pp[0], pkmn->b.pp[1], pkmn->b.pp[2], pkmn->b.pp[3]);
  printf("  pp_ups:    %4d %4d %4d %4d\n",
         pkmn->b.pp_ups[0], pkmn->b.pp_ups[1], pkmn->b.pp_ups[2], pkmn->b.pp_ups[3]);
  printf("  egg_moves: %04x %04x %04x %04x\n",
         pkmn->b.egg_moves[0], pkmn->b.egg_moves[1], pkmn->b.egg_moves[2], pkmn->b.egg_moves[3]);
  printf("  IV: %2d/%2d/%2d/%2d/%2d/%2d\n",
         (pkmn->b.iv_flags >>  0) & 0x1F,
         (pkmn->b.iv_flags >>  5) & 0x1F,
         (pkmn->b.iv_flags >> 10) & 0x1F,
         (pkmn->b.iv_flags >> 20) & 0x1F,
         (pkmn->b.iv_flags >> 25) & 0x1F,
         (pkmn->b.iv_flags >> 15) & 0x1F);
  printf("  is_egg? %c  is_nicknamed? %c\n",
         (pkmn->b.iv_flags >> 30)? 'Y' : 'N',
         (pkmn->b.iv_flags >> 31)? 'Y' : 'N');*/

  /* C block */
  /*printf("C:\n");
  printf("  OT name (if traded): '");
  print_pokemon_string(pkmn->c.ot_name_trade, 12);
  printf("'\n");*/

  /* D block */
  /*printf("D:\n");
  printf("  OT name: '");
  print_pokemon_string(pkmn->d.ot_name, 12);
  printf("'\n");

  printf("  date_egg: %2d %2d %2d   location_egg: %04x\n",
         pkmn->d.date_egg.un1, pkmn->d.date_egg.un2, pkmn->d.date_egg.un3,
         pkmn->d.location_egg);
  printf("  date_met: %2d %2d %2d   location_met: %04x\n",
         pkmn->d.date_met.un1, pkmn->d.date_met.un2, pkmn->d.date_met.un3,
         pkmn->d.location_met);
  printf("  ball: %02x  encounter_level: %d  OT gender: %c  OT game: %c\n",
         pkmn->d.ball, pkmn->d.encounter_level_flags & 0x7,
         pkmn->d.encounter_level_flags & 0x8? 'F' : 'M',
         pkmn->d.ot_game == 24? 'X' :
         pkmn->d.ot_game == 25? 'Y' : '?');
  printf("  OT country: %2d  OT region: %2d  OT 3DS region: %2d  OT lang: %2d\n",
         pkmn->d.country, pkmn->d.region, pkmn->d.region_3ds, pkmn->d.ot_language);*/
}

/* NOTE: "high-level" struct */
struct packet_ninty_2 {
  struct packet_ninty_2_header  *header;
  struct packet_ninty_2_section *sections;
  void                          *data;
  void                          *end;
};

struct packet_ninty_2 *parse_ninty_2(uint8_t *buf, uint8_t *buf_end) {
  struct packet_ninty_2_header *header = (void *) buf;

  /* Make sure that we actually have a type B chunk. */
  if (header->magic != 0xD0EA) return NULL;

  struct packet_ninty_2 *res = malloc(sizeof(struct packet_ninty_2));
  res->header   = header;
  res->sections = header->sections;

  struct packet_ninty_2_section *sec = header->sections,
                                *sec_;
  uint8_t *last = (void *) header->sections;
  while (sec < buf_end) {
    sec_ = sec;
    sec = (void *) ((uint8_t *) (sec + 1) + sec->length);

    /* end of sections */
    if (sec_->type == 0x02 || sec_->type == 0x04) break; /* TODO: difference? */

    /* TODO: hack: sometimes a chunk simply consists of no sections or payload
     * at all.  Therefore, it's necessary to check for new chunks even here. */
    if (sec_->type == 0xEA && sec_->length == 0xD0) {
      sec = sec_;
      break;
    }
  }

  /* Sanity check: Make sure we haven't exceeded the buffer boundary. */
  uint8_t *p = (void *) sec;
  assert(&p[header->size] <= buf_end);

  res->data = (void *) p;
  res->end  = (void *) (p + header->size);
  return res;
}


struct packet_ninty_3 {
  uint16_t magic;   /* 0xD0F5 */
  uint16_t un1;     /* zeroes */
  uint8_t  un2[40]; /* hash? */
} __attribute__((packed));


/*-- callback -------------------------------------------*/
int clamp(int n, int max) {
  return n > max? max : n;
}

#define CHECKSUM_COUNT 64
uint16_t checksums[CHECKSUM_COUNT];
uint8_t  checksum_idx = 0;

uint16_t ff_checksum_of(uint8_t *buf, int size) {
  union {
    uint8_t  u8[2];
    uint16_t u16;
  } __attribute__((packed)) res;
  res.u16 = 0;

  for (int i=0; i<size; i++) res.u8[i % 2] ^= buf[i];
  return res.u16;
}

void packet_callback(struct pcap_record_header *header, uint8_t *buf, int size) {
  /* Assume Ethernet, make sure that we have an IPv4 packet */
  struct header_ether *hd_ether = (void *) buf;
  endianfix_ether(hd_ether);

  if (hd_ether->type == 0x0806) { /* ARP */
    return;
  }

  if (hd_ether->type != 0x0800) { /* IPv4 */
//  printf("#### NOT IPv4! ####  (%04x)\n", hd_ether->type);
    return;
  }

  /* Have IPv4, check for UDP */
  struct header_ip *hd_ip = (void *) &buf[sizeof(struct header_ether)];
  endianfix_ip(hd_ip);

  assert(hd_ip->length == size - sizeof(struct header_ether));

  if (hd_ip->protocol == 6) { /* TCP */
  //printf("(skipping TCP packet)\n");
    return;
  }

  if (hd_ip->protocol != 17) { /* UDP */
//  printf("#### NOT UDP! ####  (%2d)\n", hd_ip->protocol);
    return;
  }

  int udp_base = sizeof(struct header_ether) + sizeof(struct header_ip);

  /* Have UDP, apply header & grab data */
  struct header_udp *hd_udp = (void *) &buf[udp_base];
  endianfix_udp(hd_udp);

  assert(hd_udp->length == size - udp_base);

  uint8_t *payload = (void *) &buf[udp_base + sizeof(struct header_udp)];
  int payload_len = hd_udp->length - sizeof(struct header_udp);
  uint8_t *payload_end = &payload[payload_len];

  /* Sanity check: packet ends after UDP payload? */
  assert(payload[payload_len    ] == 0xC4 &&
         payload[payload_len + 1] == 0xC4);

  uint16_t magic = *((uint16_t *) payload);

  /* FIXME: Temporary hacks/filters */
//if (hd_udp->length < 232) return;
//if (magic != 0xD0EA) return;  /* Only type B */
//if (magic != 0xA1AF && magic != 0xAFA1) return;  /* Only type A */
//if (hd_udp->length != 0x7F  &&
//    hd_udp->length != 0x12E &&
//    hd_udp->length != 0xFC  &&
//    hd_udp->length != 0x2E) return;

  if (hd_udp->source_port == 68 || hd_udp->dest_port == 68) return;  /* DHCP */
  if (hd_udp->source_port == 53 || hd_udp->dest_port == 53) return;  /* DNS */

  /* Check for duplicate packet */
  uint16_t csum = ff_checksum_of(payload, payload_len);
  //printf("\033[38;5;242m[%04x]\033[m", csum);
  for (int i=0; i<CHECKSUM_COUNT; i++) {
    if (checksums[i] == csum) {
      //printf("  \033[38;5;242m(repeated UDP payload)\033[m\n");
      //putchar('\n');
      return;
    }
  }
  checksums[checksum_idx++] = csum;
  checksum_idx %= CHECKSUM_COUNT;

  /* Packet header (metadata) */
/*  printf("  {\033[1m\033[38;5;%dm%08x\033[m:%04x} -> {\033[1m\033[38;5;%dm%08x\033[m:%04x} [%3x] %d.%06d\n",
         2 + hd_ip->source % 11, hd_ip->source,  hd_udp->source_port,
         2 + hd_ip->dest   % 11, hd_ip->dest,    hd_udp->dest_port,
         payload_len, header->ts_sec, header->ts_usec);*/

  int last_chunk_known = 1;
  uint8_t *p = payload;
  do {
    magic = *((uint16_t *) p);

    struct packet_ninty_1 *nin_1;
    struct packet_ninty_2 *nin_2;
    struct packet_ninty_3 *nin_3;

    switch (magic) {
      case 0xA1AF: case 0xAFA1:
        nin_1 = (void *) p;

        int hl = (nin_1->op & 0xF) == 0;
        /*if (hl) printf("\033[1;31m");
        printf("Type A: %x (%x) %2x {%02x → %02x} %2x %4x %2x :: %8x %8x\n",
               nin_1->op >> 4, nin_1->op & 0xF, nin_1->un8,
               nin_1->src, nin_1->dst,
               nin_1->un1, nin_1->un3, nin_1->un5,
               nin_1->un2, payload_len >= 0x10? nin_1->un4 : -1);
            // x1h, x2h);
        if (hl) printf("\033[m");

        hexdump_o(payload, payload_len, 0, 4);
        putchar('\n');*/

        p = payload_end;
        return;

      case 0xD0F5:
        nin_3 = (void *) p;
        //printf("Type C: %04x\n", nin_3->un1);
        p = p + sizeof(struct packet_ninty_3);
        break;

      case 0xD0EA:
        nin_2 = parse_ninty_2(p, payload_end);

        /* Chunk header metadata */
        /*printf("Type B: %x (%x) %2x [%3x]: {%02x} {%02x → %02x} %02x %4x %4x :: %2x\n",
               nin_2->header->op >> 4, nin_2->header->op & 0xF, nin_2->header->un8,
               nin_2->header->size,    nin_2->header->section_bitfield,
               nin_2->header->src,     nin_2->header->dst,
               nin_2->header->un1,
               nin_2->header->from,    nin_2->header->pack_id,
               nin_2->header->flags1);*/

        /* Look for 8E2 */
        if (nin_2->header->un8 == 0x08) {
          struct packet_ninty_2_8e2 *_8e2 = nin_2->data;

          if (_8e2->length == 0x10C) {
            struct pokemon *pkmn = decode_pokemon((void *) _8e2->data);

            //printf("~~~~ trade ~~~\n");
            dump_pokemon(pkmn);
            //putchar('\n');
            //hexdump_o((uint8_t *) pkmn, _8e2->sublength, 0, 2);
            //printf("~~~~ end   ~~~\n");
            //putchar('\n');
          }
        }

        /* Chunk sections */
        struct packet_ninty_2_section *sec = nin_2->sections;
        while (sec < nin_2->data) {

          /*  sec->type  desc
             ---------------------------------
              00         beginning_of_message
              01         checksum/key?
              02         blob_1  {payload: "part" counter; 00 for "last part" }
                                  if multipart, sometimes starts counting later
                                  than 01 (why??)  [resent packets]
              03         maybe checksum
              04         blob_2 */

          //printf("  sec: (%02x) [%02x]\n", sec->type, sec->length);
          //hexdump_o(sec->data, sec->length, 0, 4);

          /* FIXME: fugly */
          sec = (void *) (((uint8_t *) &sec[1]) + sec->length);
        }

        /* Chunk payload */
        if (nin_2->header->size > 0) {
          //printf("  payload:\n");
          //hexdump_o(nin_2->data, nin_2->header->size, 0, 4);
        }

        /* Next chunk */
        p = nin_2->end;
        break;

      default:
        //printf("[\033[1;31mUnidentified chunk\033[m]: %04x\n", magic);
        //hexdump(p, clamp(payload_end - p, 0x100));
        //putchar('\n');
        last_chunk_known = 0;
    }
  } while (last_chunk_known && p < payload_end);

//putchar('\n');
//hexdump(payload, clamp(payload_len, 0x100));
//putchar('\n');
}

int bitXor(int x, int y) {
    int a = x & y;
    int b = ~x & ~y;
    int z = ~a & ~b;
    return z;
}

/*-- main -----------------------------------------------*/
int main(void) {
  read_pcap(&packet_callback);
  return 0;
}
