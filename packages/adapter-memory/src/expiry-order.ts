export type ExpiringEntry = {
	readonly expiresAtMilliseconds: number;
	position: number;
};

const expiresBefore = (
	first: ExpiringEntry,
	second: ExpiringEntry,
): boolean => {
	return first.expiresAtMilliseconds < second.expiresAtMilliseconds;
};

export const createExpiryOrder = <Entry extends ExpiringEntry>() => {
	const heap: Entry[] = [];

	const place = (entry: Entry, position: number): void => {
		heap[position] = entry;
		entry.position = position;
	};

	const swap = (first: Entry, second: Entry): void => {
		const firstPosition = first.position;
		place(first, second.position);
		place(second, firstPosition);
	};

	const parentOf = (entry: Entry): Entry | undefined => {
		return entry.position === 0
			? undefined
			: heap[Math.floor((entry.position - 1) / 2)];
	};

	const earlierChildOf = (entry: Entry): Entry | undefined => {
		const left = heap[entry.position * 2 + 1];
		const right = heap[entry.position * 2 + 2];

		return left !== undefined &&
			right !== undefined &&
			expiresBefore(right, left)
			? right
			: left;
	};

	const siftUp = (entry: Entry): void => {
		let parent = parentOf(entry);

		while (parent !== undefined && expiresBefore(entry, parent)) {
			swap(entry, parent);
			parent = parentOf(entry);
		}
	};

	const siftDown = (entry: Entry): void => {
		let child = earlierChildOf(entry);

		while (child !== undefined && expiresBefore(child, entry)) {
			swap(entry, child);
			child = earlierChildOf(entry);
		}
	};

	return {
		earliest: (): Entry | undefined => heap[0],
		add(entry: Entry): void {
			place(entry, heap.length);
			siftUp(entry);
		},
		remove(entry: Entry): void {
			const last = heap.pop();

			if (last === undefined || last === entry) {
				return;
			}

			place(last, entry.position);
			siftDown(last);
			siftUp(last);
		},
	};
};
