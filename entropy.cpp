#include <math.h>

double element_frequency (unsigned long occurrences, unsigned long count)
{
    return ((double) occurrences) / count;
}

double entropy_of_distribution (
        unsigned long count,
        unsigned long *distribution,
        unsigned long classes
        )
{
    int i;
    double sum, freq;
    for (i = 0; i < classes; ++i) {
        freq = element_frequency(distribution[i], count);
        sum += freq * log(freq);
    }

    return sum;
}
