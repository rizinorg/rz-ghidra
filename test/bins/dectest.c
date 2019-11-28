
int global_var = 42;

int get_global_var() {
	return global_var;
}

int global_array[2] = { 1337, 123 };

int get_global_array_entry() {
	return global_array[1];
}

int main() {
	return 0;
}

