#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>

#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))
#define GALOIS_INV {0x0e, 0x09, 0x0d, 0x0b}
#define GALOIS {0x02, 0x01, 0x01, 0x03}

/*
 * sbox create
 */

void initialize_aes_sbox(uint8_t *sbox)
{
	uint8_t p = 1, q = 1;
	uint8_t xformed;
	do
	{
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= q & 0x80 ? 0x09 : 0;

		xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);
		sbox[p] = xformed ^ 0x63;
	}while (p != 1);

	sbox[0] = 0x63;
}

/*
 * operation simple
 */

void
xor_mat(uint8_t *state, uint8_t *key)
{
	int i = 0;
	while(i < 16)
	{
		i[state] ^= i[key];
		++i;
	}
}

void
sub_bytes(uint8_t *state, uint8_t *sbox)
{
	int i = 0;

	while(i < 16)
	{
		*(i + state) = (*(i + state))[sbox];
		++i;
	}
}

void
rotate(uint32_t *mat)
{
	1[mat] = (1[mat] >> 8) ^ (1[mat] << 24);
	2[mat] = ((2[mat] & 0xffff) << 16) ^ ((2[mat] >> 16) & 0xffff);
	3[mat] = (3[mat] << 8) ^ (3[mat] >> 24);

}

void
rotate_rev(uint32_t *mat)
{
	1[mat] = (1[mat] << 8) ^ (1[mat] >> 24);
	2[mat] = ((2[mat] & 0xffff) << 16) ^ ((2[mat] >> 16) & 0xffff);
	3[mat] = (3[mat] >> 8) ^ (3[mat] << 24);
}


/*
* galois
*/

__attribute__((always_inline)) uint8_t
gmult2(uint8_t nb)
{
	int8_t test;

	test = nb & 0x80;
	nb <<= 1;
	if (test)
		nb ^= 0x1b;
	return (nb);
}

__attribute__((always_inline)) uint8_t
gmult(uint8_t a, uint8_t b)
{

	uint8_t p = 0;
	uint8_t i = 0;
	uint8_t test = 0;

	while (i < 8)
	{
		if (b & 1)
			p ^= a;

		a = gmult2(a);
		b >>= 1;
		++i;
	}

	return (p);
}

void
mix_columns(uint8_t *state, uint8_t *matrix)
{
	uint8_t result[4];
	uint8_t inc = 0;
	while (inc < 4)
	{
		result[0] = gmult(state[inc],matrix[0])^gmult(state[inc + 0x4],matrix[3])^gmult(state[inc + 0x8],matrix[2])^gmult(state[inc + 0xc],matrix[1]);
		result[1] = gmult(state[inc],matrix[1])^gmult(state[inc + 0x4],matrix[0])^gmult(state[inc + 0x8],matrix[3])^gmult(state[inc + 0xc],matrix[2]);
		result[2] = gmult(state[inc],matrix[2])^gmult(state[inc + 0x4],matrix[1])^gmult(state[inc + 0x8],matrix[0])^gmult(state[inc + 0xc],matrix[3]);
		result[3] = gmult(state[inc],matrix[3])^gmult(state[inc + 0x4],matrix[2])^gmult(state[inc + 0x8],matrix[1])^gmult(state[inc + 0xc],matrix[0]);
		state[inc + 0x0] = result[0];
		state[inc + 0x4] = result[1];
		state[inc + 0x8] = result[2];
		state[inc + 0xc] = result[3];
		++inc;
	}
}

/*
 * key schedule
 */

	void
xor_key(uint8_t *key, uint8_t *new_key, uint8_t *yolo)
{
	uint8_t j, i = 0;

	while(i <= 4)
	{
		j = 0;
		while(j <= 4)
		{
			if (!i)
				(j << 2)[new_key] = (j << 2)[key] ^ j[yolo];
			else
				((j << 2) + i)[new_key] = ((j << 2) + i)[key] ^ ((j << 2) + i - 1)[new_key];
			++j;
		}
		++i;
	}
}

	void
key_schedule(uint8_t *key, uint8_t *new_key, uint8_t *sbox, uint8_t *rcon)
{
	uint8_t tmp[4];

	0[tmp] = (7[key])[sbox];
	1[tmp] = (11[key])[sbox];
	2[tmp] = (15[key])[sbox];
	3[tmp] = (3[key])[sbox];

	0[new_key] ^= *rcon;
	xor_key(key, new_key, tmp);
	*rcon = gmult2(*rcon);
}

/*
 * cypher
 */

void
rev_sbox(uint8_t *sbox)
{
	uint8_t sbox_tmp[256];
	uint8_t inc;

	inc = 0;
	while(1)
	{
		sbox_tmp[inc[sbox]] = inc;
		++inc;
		if (!inc)
			break;
	}
	while(1)
	{
		inc[sbox] = sbox_tmp[inc];
		++inc;
		if (!inc)
			break;
	}
}

void
decyphern(uint8_t *in, uint8_t *state, uint8_t *key, size_t n) // n == blocs de 128
{
	uint8_t sbox[256];
	uint8_t matrix[] = GALOIS_INV;
	uint8_t inc = 0;
	uint8_t *key_table;
	uint8_t round;


	initialize_aes_sbox(sbox);
//key
	uint8_t *all_key = malloc(0x10 * 10);
	uint8_t rcon = 1;
	while (inc < 10)
	{
		if (!inc)
			key_schedule(key, all_key, sbox, &rcon);
		else
			key_schedule(all_key + ((inc - 1) << 4), all_key + (inc << 4), sbox, &rcon);
		++inc;
	}
	rev_sbox(sbox);

	inc = 0;
	while(n)
	{
		state[inc] = in[inc];
		++inc;
		if (inc != 16)
			continue ;

		round = 10;
		while(round)
		{
			--round;
			xor_mat(state, all_key + (round << 4));
			if (round != 9)
				mix_columns(state, matrix);
			rotate_rev((void *)state);
			sub_bytes(state, sbox);
		}
		xor_mat(state, key);

		inc = 0;
		in += 16;
		state += 16;
		--n;
	}
	free(all_key);
}

void
cyphern(uint8_t *in, uint8_t *state, uint8_t *key, size_t n) // n == blocs de 128
{
	uint8_t inc = 0;
	uint8_t sbox[256];
	uint8_t matrix[] = GALOIS;
	uint8_t round;

	initialize_aes_sbox(sbox);
//key
	uint8_t *all_key = malloc(0x10 * 10);
	uint8_t rcon = 1;
	while (inc < 10)
	{
		if (!inc)
			key_schedule(key, all_key, sbox, &rcon);
		else
			key_schedule(all_key + ((inc - 1) << 4), all_key + (inc << 4), sbox, &rcon);
		++inc;
	}
//cypher	
	inc = 0;
	while(n)
	{
		state[inc] = in[inc];
		++inc;
		if (inc != 16)
			continue ;

		round = 0;
		xor_mat(state, key);
		while(round < 10)
		{
			sub_bytes(state, sbox); // reverse box
			rotate((void *)state);
			if (round != 9)
				mix_columns(state, matrix);
			xor_mat(state, all_key + (round << 4));
			++round;
		}
		inc = 0;
		in += 16;
		state += 16;
		--n;
	}
	free(all_key);
}

int main()
{
	char *str;
	char *str2;
	char *str3;
	uint8_t key[16];

	str = malloc(4096);
	str2 = malloc(4096);
	str3 = malloc(4096);

	memset(str, 0, 4096);
//	init_state((void *)str);
	
	FILE *fs;
	if ((fs = fopen("test" , "r")) == 0)
		return (1);
	fread(str,sizeof *str, 4085, fs);
	fclose (fs);
	
	if ((fs = fopen("key" , "r")) == 0)
		return (1);
	fread((void *)key, sizeof *key, 16, fs);
	fclose (fs);

    //dprintf(1,"%s\n", str);
	cyphern((void *)str, (void *)str2, key, 256);
	write(2, str2, 4096);
	decyphern((void *) str2, (void*)str3, key, 256);
	write(3,str3, 4085);
}

